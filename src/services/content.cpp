#include "content.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <tuple>
#include <vector>

namespace services {

namespace {

const hk::Result kUnknown = MakeResult(10, 221);
const hk::Result kContentNotFound = MakeResult(5, 2);      // ncm
const hk::Result kContentMetaNotFound = MakeResult(5, 7);  // ncm
const hk::Result kUnknownStorage = MakeResult(5, 160);     // ncm: a storage it does not have
const hk::Result kProgramNotFound = MakeResult(8, 2);      // lr
const hk::Result kDataNotFound = MakeResult(8, 3);         // lr
const hk::Result kAddOnContentNotFound = MakeResult(8, 7); // lr
const hk::Result kControlNotFound = MakeResult(8, 8);      // lr

// Storage ids.
constexpr uint8_t kGameCard = 2, kBuiltInSystem = 3, kBuiltInUser = 4, kSdCard = 5;

// Content meta types and content types that resolution looks at.
constexpr uint8_t kApplication = 0x80, kPatch = 0x81, kAddOnContent = 0x82;
constexpr uint8_t kProgramContent = 1, kDataContent = 2, kControlContent = 3, kHtmlDocumentContent = 4,
                  kLegalInformationContent = 5;

using ContentId = std::array<std::byte, 16>;

// A ContentMetaKey: id, version, type, install type, two bytes of padding.
struct Key {
    uint64_t id{};
    uint32_t version{};
    uint8_t type{}, install{};
    auto Tie() const { return std::tie(id, version, type, install); }
    bool operator<(const Key& other) const { return Tie() < other.Tie(); }
    bool operator==(const Key& other) const { return Tie() == other.Tie(); }

    static Key From(const Request& request, size_t at) {
        Key key;
        key.id = request.In<uint64_t>(at);
        key.version = request.In<uint32_t>(at + 8);
        key.type = request.In<uint8_t>(at + 12);
        key.install = request.In<uint8_t>(at + 13);
        return key;
    }
    std::array<std::byte, 16> Bytes() const {
        std::array<std::byte, 16> out{};
        std::memcpy(&out[0], &id, 8);
        std::memcpy(&out[8], &version, 4);
        out[12] = static_cast<std::byte>(type);
        out[13] = static_cast<std::byte>(install);
        return out;
    }
};

// A content meta as ncm keeps it: a header (extended header size, content
// count, content meta count, attributes, storage id), the extended header,
// ContentInfo[] (0x18 bytes: id, 40-bit size, attributes, type, id offset)
// and ContentMetaInfo[] (0x10 bytes).
struct Meta {
    std::vector<std::byte> value;

    uint16_t U16(size_t at) const {
        uint16_t v = 0;
        if (at + 2 <= value.size())
            std::memcpy(&v, &value[at], 2);
        return v;
    }
    size_t ExtendedSize() const { return U16(0); }
    size_t ContentCount() const { return U16(2); }
    size_t MetaCount() const { return U16(4); }
    uint8_t Attributes() const { return value.size() > 6 ? static_cast<uint8_t>(value[6]) : 0; }
    size_t Infos() const { return 8 + ExtendedSize(); }
    size_t MetaInfos() const { return Infos() + ContentCount() * 0x18; }
    bool Valid() const { return value.size() >= 8 && MetaInfos() + MetaCount() * 0x10 <= value.size(); }
    template <class T> T Extended(size_t at) const {
        T v{};
        if (at + sizeof(T) <= ExtendedSize())
            std::memcpy(&v, &value[8 + at], sizeof(T));
        return v;
    }
    std::span<const std::byte> Info(size_t i) const { return std::span(value).subspan(Infos() + i * 0x18, 0x18); }
    ContentId InfoId(size_t i) const {
        ContentId id;
        std::copy_n(Info(i).begin(), 16, id.begin());
        return id;
    }
    uint8_t InfoType(size_t i) const { return static_cast<uint8_t>(Info(i)[0x16]); }
    uint8_t InfoOffset(size_t i) const { return static_cast<uint8_t>(Info(i)[0x17]); }

    // A patch's, add-on's or delta's application; an application's own id.
    uint64_t ApplicationId(const Key& key) const {
        return key.type == kPatch || key.type == kAddOnContent || key.type == 0x83 ? Extended<uint64_t>(0) : key.id;
    }
    bool Find(uint8_t type, uint8_t id_offset, ContentId& out) const {
        for (size_t i = 0; i < ContentCount(); ++i) {
            if (InfoType(i) == type && InfoOffset(i) == id_offset) {
                out = InfoId(i);
                return true;
            }
        }
        return false;
    }
};

struct Location {
    std::string file;
    uint64_t offset{}, size{};
    std::array<std::byte, 16> rights_id{}; // zero: the content has none
    uint8_t key_generation{};
};

struct Storage {
    uint8_t id{};
    std::map<Key, Meta> metas;
    std::map<ContentId, Location> contents;

    // The newest content meta with this id, if any.
    const std::pair<const Key, Meta>* Latest(uint64_t meta_id) const {
        const std::pair<const Key, Meta>* best = nullptr;
        for (const auto& entry : metas)
            if (entry.first.id == meta_id && (!best || entry.first.version > best->first.version))
                best = &entry;
        return best;
    }
};

std::string Hex(std::span<const std::byte> bytes) {
    std::string out;
    for (std::byte b : bytes) {
        char two[3];
        std::snprintf(two, sizeof two, "%02x", static_cast<unsigned>(b));
        out += two;
    }
    return out;
}

// The path a content has, as ncm's GetPath and lr give it to fs.
std::string PathOf(uint8_t storage, const ContentId& id) {
    const char* mount = storage == kBuiltInSystem ? "@SystemContent" : storage == kBuiltInUser ? "@UserContent"
                        : storage == kSdCard      ? "@SdCardContent"
                                                  : "@GcApp";
    return std::string(mount) + "://registered/" + Hex(id) + ".nca";
}

// lr::Path: a NUL-terminated string in 0x300 bytes.
std::vector<std::byte> PathBytes(const std::string& path) {
    std::vector<std::byte> out(0x300);
    std::memcpy(out.data(), path.data(), std::min(path.size(), out.size() - 1));
    return out;
}

struct ContentStore {
    std::map<uint8_t, Storage> storages;

    Storage* Find(uint8_t id) {
        auto it = storages.find(id);
        return it == storages.end() ? nullptr : &it->second;
    }

    void Load(const std::string& folder) {
        for (uint8_t id : {kGameCard, kBuiltInSystem, kBuiltInUser, kSdCard})
            storages[id].id = id;
        if (folder.empty())
            return;
        const std::pair<uint8_t, const char*> names[] = {{kBuiltInSystem, "BuiltInSystem"},
                                                         {kBuiltInUser, "BuiltInUser"}};
        size_t total = 0;
        for (const auto& [id, name] : names) {
            const std::filesystem::path dir = std::filesystem::path(folder) / name;
            if (!std::filesystem::is_directory(dir))
                continue;
            Storage& storage = storages[id];
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (entry.path().extension() != ".meta")
                    continue;
                // <id>_<version>_<type>_<install type>.meta
                std::istringstream fields(entry.path().stem().string());
                std::string part[4];
                for (auto& p : part)
                    std::getline(fields, p, '_');
                Key key{std::stoull(part[0], nullptr, 16), static_cast<uint32_t>(std::stoul(part[1])),
                        static_cast<uint8_t>(std::stoul(part[2])), static_cast<uint8_t>(std::stoul(part[3]))};
                std::ifstream file(entry.path(), std::ios::binary);
                Meta meta;
                meta.value.resize(static_cast<size_t>(entry.file_size()));
                file.read(reinterpret_cast<char*>(meta.value.data()), static_cast<std::streamsize>(meta.value.size()));
                if (meta.Valid())
                    storage.metas[key] = std::move(meta);
            }
            // contents.txt: content id, offset, size, rights id, key
            // generation, then the file to the line's end.
            std::ifstream list(dir / "contents.txt");
            for (std::string line; std::getline(list, line);) {
                std::istringstream fields(line);
                std::string hex, offset, size, rights, generation, file;
                if (!(fields >> hex >> offset >> size >> rights >> generation) || hex.size() != 32 ||
                    rights.size() != 32)
                    continue;
                std::getline(fields >> std::ws, file);
                ContentId content{};
                Location location{file, std::stoull(offset, nullptr, 0), std::stoull(size, nullptr, 0)};
                for (size_t i = 0; i < 16; ++i) {
                    content[i] = static_cast<std::byte>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
                    location.rights_id[i] = static_cast<std::byte>(std::stoul(rights.substr(i * 2, 2), nullptr, 16));
                }
                location.key_generation = static_cast<uint8_t>(std::stoul(generation));
                storage.contents[content] = location;
            }
            total += storage.metas.size();
        }
        std::fprintf(stderr, "ncm: %zu content metas from %s\n", total, folder.c_str());
    }
};

// ncm IContentMetaDatabase.
class MetaDatabase final : public Interface {
public:
    explicit MetaDatabase(Storage& storage) : storage_(storage) {}
    const char* Name() const override { return "ncm IContentMetaDatabase"; }
    hk::Result Handle(const Request& request, Response& response) override {
        auto& metas = storage_.metas;
        const auto find = [&](const Key& key) -> const Meta* {
            auto it = metas.find(key);
            return it == metas.end() ? nullptr : &it->second;
        };
        switch (request.command) {
        case 0: { // Set(key, A value)
            Meta meta;
            meta.value = request.InBuffer(0);
            if (!meta.Valid())
                return kContentMetaNotFound;
            metas[Key::From(request, 0)] = std::move(meta);
            return 0;
        }
        case 1: { // Get(key) -> u64 size, B value
            const Meta* meta = find(Key::From(request, 0));
            if (!meta)
                return kContentMetaNotFound;
            request.OutBuffer(std::span(meta->value).first(
                std::min(meta->value.size(), request.receives.empty() ? meta->value.size() : request.receives[0].size)));
            response.Out(static_cast<uint64_t>(meta->value.size()));
            return 0;
        }
        case 2: // Remove(key)
            return metas.erase(Key::From(request, 0)) ? 0 : kContentMetaNotFound;
        case 3:    // GetContentIdByType(key, u8 type) -> content id
        case 20: { // GetContentIdByTypeAndIdOffset(key, u8 type, u8 id offset) -> content id
            const Meta* meta = find(Key::From(request, 0));
            ContentId id;
            if (!meta)
                return kContentMetaNotFound;
            if (!meta->Find(request.In<uint8_t>(0x10), request.command == 20 ? request.In<uint8_t>(0x11) : 0, id))
                return kContentNotFound;
            response.Out(id);
            return 0;
        }
        case 25: { // GetContentInfoByTypeAndIdOffset(u8 type, u8 id offset, key at 8) -> ContentInfo
            // A ContentInfo has its content type at 0x16 and id offset at 0x17.
            const Meta* meta = find(Key::From(request, 8));
            if (!meta)
                return kContentMetaNotFound;
            for (size_t i = 0; i < meta->ContentCount(); ++i) {
                const auto info = meta->Info(i);
                if (info[0x16] == std::byte{request.In<uint8_t>(0)} && info[0x17] == std::byte{request.In<uint8_t>(1)}) {
                    std::array<std::byte, 0x18> out;
                    std::copy(info.begin(), info.end(), out.begin());
                    response.Out(out);
                    return 0;
                }
            }
            return kContentNotFound;
        }
        case 4: { // ListContentInfo(s32 offset, key at 8) -> s32 count, B ContentInfo[]
            const Meta* meta = find(Key::From(request, 8));
            if (!meta)
                return kContentMetaNotFound;
            const size_t offset = static_cast<size_t>(std::max(0, request.In<int32_t>(0)));
            const size_t capacity = request.receives.empty() ? 0 : request.receives[0].size / 0x18;
            std::vector<std::byte> out;
            for (size_t i = offset; i < meta->ContentCount() && out.size() / 0x18 < capacity; ++i)
                out.insert(out.end(), meta->Info(i).begin(), meta->Info(i).end());
            if (!out.empty())
                request.OutBuffer(out);
            response.Out(static_cast<int32_t>(out.size() / 0x18));
            return 0;
        }
        case 5: { // List(u8 type, u64 application id, u64 min, u64 max, u8 install type) -> s32 total, s32 written, B keys
            const uint8_t type = request.In<uint8_t>(0), install = request.In<uint8_t>(0x20);
            const uint64_t application = request.In<uint64_t>(8), min = request.In<uint64_t>(0x10),
                           max = request.In<uint64_t>(0x18);
            const size_t capacity = request.receives.empty() ? 0 : request.receives[0].size / 0x10;
            std::vector<std::byte> out;
            int32_t total = 0;
            for (const auto& [key, meta] : metas) {
                if ((type && key.type != type) || key.id < min || key.id > max || key.install != install ||
                    (application && meta.ApplicationId(key) != application))
                    continue;
                ++total;
                if (out.size() / 0x10 < capacity) {
                    const auto bytes = key.Bytes();
                    out.insert(out.end(), bytes.begin(), bytes.end());
                }
            }
            if (!out.empty())
                request.OutBuffer(out);
            response.Out(std::array<int32_t, 2>{total, static_cast<int32_t>(out.size() / 0x10)});
            return 0;
        }
        case 6: { // GetLatestContentMetaKey(u64 id) -> key
            const auto* latest = storage_.Latest(request.In<uint64_t>(0));
            if (!latest)
                return kContentMetaNotFound;
            response.Out(latest->first.Bytes());
            return 0;
        }
        case 7: { // ListApplication(u8 type) -> s32 total, s32 written, B ApplicationContentMetaKey[]
            const uint8_t type = request.In<uint8_t>(0);
            const size_t capacity = request.receives.empty() ? 0 : request.receives[0].size / 0x18;
            std::vector<std::byte> out;
            int32_t total = 0;
            for (const auto& [key, meta] : metas) {
                if ((type && key.type != type) ||
                    (key.type != kApplication && key.type != kPatch && key.type != kAddOnContent && key.type != 0x83))
                    continue;
                ++total;
                if (out.size() / 0x18 < capacity) {
                    const auto bytes = key.Bytes();
                    const uint64_t application = meta.ApplicationId(key);
                    out.insert(out.end(), bytes.begin(), bytes.end());
                    const auto* id = reinterpret_cast<const std::byte*>(&application);
                    out.insert(out.end(), id, id + 8);
                }
            }
            if (!out.empty())
                request.OutBuffer(out);
            response.Out(std::array<int32_t, 2>{total, static_cast<int32_t>(out.size() / 0x18)});
            return 0;
        }
        case 8: // Has(key) -> bool
            response.Out(static_cast<uint8_t>(find(Key::From(request, 0)) != nullptr));
            return 0;
        case 9: { // HasAll(A keys) -> bool
            const auto keys = request.InBuffer(0);
            bool all = true;
            for (size_t at = 0; at + 0x10 <= keys.size(); at += 0x10) {
                Key key;
                std::memcpy(&key.id, &keys[at], 8);
                std::memcpy(&key.version, &keys[at + 8], 4);
                key.type = static_cast<uint8_t>(keys[at + 12]);
                key.install = static_cast<uint8_t>(keys[at + 13]);
                all = all && find(key);
            }
            response.Out(static_cast<uint8_t>(all));
            return 0;
        }
        case 10: { // GetSize(key) -> u64
            const Meta* meta = find(Key::From(request, 0));
            if (!meta)
                return kContentMetaNotFound;
            response.Out(static_cast<uint64_t>(meta->value.size()));
            return 0;
        }
        case 11:   // GetRequiredSystemVersion(key) -> u32
        case 19: { // GetRequiredApplicationVersion(key) -> u32
            const Key key = Key::From(request, 0);
            const Meta* meta = find(key);
            if (!meta)
                return kContentMetaNotFound;
            // Application: patch id, required system version, required
            // application version. Patch: application id, required system
            // version. Add-on: application id, required application version.
            if (request.command == 11 && (key.type == kApplication || key.type == kPatch))
                response.Out(meta->Extended<uint32_t>(8));
            else if (request.command == 19 && key.type == kAddOnContent)
                response.Out(meta->Extended<uint32_t>(8));
            else if (request.command == 19 && key.type == kApplication)
                response.Out(meta->Extended<uint32_t>(12));
            else
                return kContentMetaNotFound;
            return 0;
        }
        case 12: { // GetPatchContentMetaId(key) -> u64
            const Key key = Key::From(request, 0);
            const Meta* meta = find(key);
            if (!meta || key.type != kApplication)
                return kContentMetaNotFound;
            response.Out(meta->Extended<uint64_t>(0));
            return 0;
        }
        case 13: // DisableForcibly
        case 15: // Commit
            return 0;
        case 14: { // LookupOrphanContent(A content ids) -> B bools: none is an orphan
            const auto ids = request.InBuffer(0);
            request.OutBuffer(std::vector<std::byte>(ids.size() / 16));
            return 0;
        }
        case 16: { // HasContent(key, content id) -> bool
            const Meta* meta = find(Key::From(request, 0));
            if (!meta)
                return kContentMetaNotFound;
            ContentId id;
            std::memcpy(id.data(), request.raw.data() + std::min<size_t>(0x10, request.raw.size()),
                        std::min<size_t>(16, request.raw.size() > 0x10 ? request.raw.size() - 0x10 : 0));
            bool has = false;
            for (size_t i = 0; i < meta->ContentCount(); ++i)
                has = has || meta->InfoId(i) == id;
            response.Out(static_cast<uint8_t>(has));
            return 0;
        }
        case 17: { // ListContentMetaInfo(key, s32 offset) -> s32 count, B ContentMetaInfo[]
            const Meta* meta = find(Key::From(request, 0));
            if (!meta)
                return kContentMetaNotFound;
            const size_t offset = static_cast<size_t>(std::max(0, request.In<int32_t>(0x10)));
            const size_t capacity = request.receives.empty() ? 0 : request.receives[0].size / 0x10;
            std::vector<std::byte> out;
            for (size_t i = offset; i < meta->MetaCount() && out.size() / 0x10 < capacity; ++i) {
                const auto info = std::span(meta->value).subspan(meta->MetaInfos() + i * 0x10, 0x10);
                out.insert(out.end(), info.begin(), info.end());
            }
            if (!out.empty())
                request.OutBuffer(out);
            response.Out(static_cast<int32_t>(out.size() / 0x10));
            return 0;
        }
        case 18: { // GetAttributes(key) -> u8
            const Meta* meta = find(Key::From(request, 0));
            if (!meta)
                return kContentMetaNotFound;
            response.Out(meta->Attributes());
            return 0;
        }
        case 21: // GetCount -> u32
            response.Out(static_cast<uint32_t>(metas.size()));
            return 0;
        case 22: { // GetOwnerApplicationId(key) -> u64
            const Key key = Key::From(request, 0);
            const Meta* meta = find(key);
            if (!meta)
                return kContentMetaNotFound;
            response.Out(meta->ApplicationId(key));
            return 0;
        }
        default:
            return kUnknown;
        }
    }

private:
    Storage& storage_;
};

ContentId IdArgument(const Request& request, size_t at) {
    ContentId id{};
    for (size_t i = 0; i < 16; ++i)
        id[i] = static_cast<std::byte>(request.In<uint8_t>(at + i));
    return id;
}

// ncm IContentStorage: read only, with no placeholders (installs make them).
class ContentStorage final : public Interface {
public:
    explicit ContentStorage(Storage& storage) : storage_(storage) {}
    const char* Name() const override { return "ncm IContentStorage"; }
    hk::Result Handle(const Request& request, Response& response) override {
        auto& contents = storage_.contents;
        switch (request.command) {
        case 7: // Has(content id) -> bool
            response.Out(static_cast<uint8_t>(contents.contains(IdArgument(request, 0))));
            return 0;
        case 8: { // GetPath(content id) -> C path
            const ContentId id = IdArgument(request, 0);
            if (!contents.contains(id))
                return kContentNotFound;
            request.OutBuffer(PathBytes(PathOf(storage_.id, id)));
            return 0;
        }
        case 3: // HasPlaceHolder(placeholder id) -> bool: installs make placeholders, and there are none
            response.Out(uint8_t{0});
            return 0;
        case 10: // CleanupAllPlaceHolder
            return 0;
        case 11: // ListPlaceHolder -> s32 count, B ids
            response.Out(int32_t{0});
            return 0;
        case 12: // GetContentCount -> s32
            response.Out(static_cast<int32_t>(contents.size()));
            return 0;
        case 13: { // ListContentId(s32 offset) -> s32 count, B content ids
            const size_t offset = static_cast<size_t>(std::max(0, request.In<int32_t>(0)));
            const size_t capacity = request.receives.empty() ? 0 : request.receives[0].size / 16;
            std::vector<std::byte> out;
            size_t i = 0;
            for (const auto& [id, location] : contents) {
                if (i++ < offset)
                    continue;
                if (out.size() / 16 == capacity)
                    break;
                out.insert(out.end(), id.begin(), id.end());
            }
            if (!out.empty())
                request.OutBuffer(out);
            response.Out(static_cast<int32_t>(out.size() / 16));
            return 0;
        }
        case 14: { // GetSizeFromContentId(content id) -> s64
            auto it = contents.find(IdArgument(request, 0));
            if (it == contents.end())
                return kContentNotFound;
            response.Out(static_cast<int64_t>(it->second.size));
            return 0;
        }
        case 20: { // GetRightsIdFromContentId(content id, u8 attribute) -> RightsId
            // RightsId: the rights id, then the key generation at 0x10.
            auto it = contents.find(IdArgument(request, 0));
            if (it == contents.end())
                return kContentNotFound;
            std::array<std::byte, 0x18> rights{};
            std::copy(it->second.rights_id.begin(), it->second.rights_id.end(), rights.begin());
            rights[0x10] = std::byte{it->second.key_generation};
            response.Out(rights);
            return 0;
        }
        case 22: // GetFreeSpaceSize -> s64: full
            response.Out(int64_t{0});
            return 0;
        case 23: { // GetTotalSpaceSize -> s64: what it holds
            int64_t total = 0;
            for (const auto& [id, location] : contents)
                total += static_cast<int64_t>(location.size);
            response.Out(total);
            return 0;
        }
        default:
            return kUnknown;
        }
    }

private:
    Storage& storage_;
};

// ncm: IContentManager.
class ContentManager final : public Interface {
public:
    explicit ContentManager(std::shared_ptr<ContentStore> store) : store_(std::move(store)) {}
    const char* Name() const override { return "ncm"; }
    hk::Result Handle(const Request& request, Response& response) override {
        Storage* storage = store_->Find(request.In<uint8_t>(0));
        switch (request.command) {
        case 0:  // CreateContentStorage(storage)
        case 1:  // CreateContentMetaDatabase(storage)
        case 2:  // VerifyContentStorage(storage)
        case 3:  // VerifyContentMetaDatabase(storage)
        case 8:  // CleanupContentMetaDatabase(storage)
        case 9:  // ActivateContentStorage(storage)
        case 10: // InactivateContentStorage(storage)
        case 11: // ActivateContentMetaDatabase(storage)
        case 12: // InactivateContentMetaDatabase(storage)
            return storage ? 0 : kUnknownStorage;
        case 13: // InvalidateRightsIdCache
            return 0;
        case 14: // GetMemoryReport -> four memory resource states (system, user, game card, heap), 0x20 bytes each
            response.Out(std::array<uint64_t, 16>{}); // the index is the host's, not a guest heap's
            return 0;
        case 4: // OpenContentStorage(storage) -> IContentStorage
            if (!storage)
                return kUnknownStorage;
            response.objects.push_back(std::make_shared<ContentStorage>(*storage));
            return 0;
        case 5: // OpenContentMetaDatabase(storage) -> IContentMetaDatabase
            if (!storage)
                return kUnknownStorage;
            response.objects.push_back(std::make_shared<MetaDatabase>(*storage));
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::shared_ptr<ContentStore> store_;
};

// The path of a content of an id's newest content meta, preferring a
// patch's program over the application's own.
bool Resolve(const Storage& storage, uint64_t id, uint8_t content_type, std::string& path) {
    const auto* latest = storage.Latest(id);
    if (!latest)
        return false;
    ContentId content;
    if (content_type == kProgramContent && latest->first.type == kApplication) {
        // A patch's id is the application's plus 0x800.
        const auto* patch = storage.Latest(id + 0x800);
        if (patch && patch->first.type == kPatch && patch->second.Find(content_type, 0, content)) {
            path = PathOf(storage.id, content);
            return true;
        }
    }
    if (!latest->second.Find(content_type, 0, content))
        return false;
    path = PathOf(storage.id, content);
    return true;
}

// lr ILocationResolver for one storage: redirections first, then the
// storage's content metas.
class LocationResolver final : public Interface {
public:
    explicit LocationResolver(Storage& storage) : storage_(storage) {}
    const char* Name() const override { return "lr ILocationResolver"; }
    hk::Result Handle(const Request& request, Response& response) override {
        (void)response;
        const uint64_t id = request.In<uint64_t>(0);
        const auto resolve = [&](uint8_t kind, uint8_t content_type, hk::Result missing) {
            std::string path;
            if (auto it = redirections_.find({kind, id}); it != redirections_.end())
                path = it->second;
            else if (!Resolve(storage_, id, content_type, path))
                return missing;
            request.OutBuffer(PathBytes(path));
            return hk::Result{0};
        };
        const auto redirect = [&](uint8_t kind) {
            const auto bytes = request.InBuffer(0);
            std::string path(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            path.resize(std::strlen(path.c_str()));
            redirections_[{kind, id}] = path;
            return hk::Result{0};
        };
        switch (request.command) {
        case 0: // ResolveProgramPath(u64 id) -> C path
            return resolve(kProgramContent, kProgramContent, kProgramNotFound);
        case 1:  // RedirectProgramPath(u64 id, X path)
        case 10: // RedirectApplicationProgramPath(u64 id, u64 owner, X path)
            return redirect(kProgramContent);
        case 2: // ResolveApplicationControlPath(u64 id) -> C path
            return resolve(kControlContent, kControlContent, kControlNotFound);
        case 3: // ResolveApplicationHtmlDocumentPath(u64 id) -> C path
            return resolve(kHtmlDocumentContent, kHtmlDocumentContent, kControlNotFound);
        case 4: // ResolveDataPath(u64 id) -> C path
            return resolve(kDataContent, kDataContent, kDataNotFound);
        case 5: // RedirectApplicationControlPath
            return redirect(kControlContent);
        case 6: // RedirectApplicationHtmlDocumentPath
            return redirect(kHtmlDocumentContent);
        case 7: // ResolveApplicationLegalInformationPath(u64 id) -> C path
            return resolve(kLegalInformationContent, kLegalInformationContent, kControlNotFound);
        case 8: // RedirectApplicationLegalInformationPath
            return redirect(kLegalInformationContent);
        case 9: // Refresh
            return 0;
        case 11: // ClearApplicationRedirection
            redirections_.clear();
            return 0;
        case 12: // EraseProgramRedirection(u64 id)
        case 13: // EraseApplicationControlRedirection(u64 id)
        case 14: // EraseApplicationHtmlDocumentRedirection(u64 id)
        case 15: { // EraseApplicationLegalInformationRedirection(u64 id)
            static constexpr uint8_t kinds[] = {kProgramContent, kControlContent, kHtmlDocumentContent,
                                                kLegalInformationContent};
            redirections_.erase({kinds[request.command - 12], id});
            return 0;
        }
        default:
            return kUnknown;
        }
    }

private:
    Storage& storage_;
    std::map<std::pair<uint8_t, uint64_t>, std::string> redirections_;
};

// lr IRegisteredLocationResolver: only what has been registered resolves.
class RegisteredLocationResolver final : public Interface {
public:
    const char* Name() const override { return "lr IRegisteredLocationResolver"; }
    hk::Result Handle(const Request& request, Response&) override {
        const uint64_t id = request.In<uint64_t>(0);
        switch (request.command) {
        case 0: { // ResolveProgramPath(u64 id) -> C path
            auto it = programs_.find(id);
            if (it == programs_.end())
                return kProgramNotFound;
            request.OutBuffer(PathBytes(it->second));
            return 0;
        }
        case 1: // RegisterProgramPath(u64 id, u64 owner, X path)
        case 3: { // RedirectProgramPath(u64 id, u64 owner, X path)
            const auto bytes = request.InBuffer(0);
            std::string path(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            path.resize(std::strlen(path.c_str()));
            programs_[id] = path;
            return 0;
        }
        case 2: // UnregisterProgramPath(u64 id)
            programs_.erase(id);
            return 0;
        case 8: // Refresh
        case 9: // RefreshExcluding
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::map<uint64_t, std::string> programs_;
};

// lr IAddOnContentLocationResolver: add-ons resolve to their data content
// in the user's storage.
class AddOnContentLocationResolver final : public Interface {
public:
    explicit AddOnContentLocationResolver(Storage& user) : user_(user) {}
    const char* Name() const override { return "lr IAddOnContentLocationResolver"; }
    hk::Result Handle(const Request& request, Response&) override {
        switch (request.command) {
        case 0: { // ResolveAddOnContentPath(u64 id) -> C path
            std::string path;
            if (!Resolve(user_, request.In<uint64_t>(0), kDataContent, path))
                return kAddOnContentNotFound;
            request.OutBuffer(PathBytes(path));
            return 0;
        }
        case 1: // RegisterAddOnContentStorage(u64 id, u64 application id, u8 storage)
        case 2: // UnregisterAllAddOnContentPath
        case 3: // RefreshApplicationAddOnContent(A ids)
        case 4: // UnregisterApplicationAddOnContent(u64 application id)
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    Storage& user_;
};

// lr: ILocationResolverManager.
class LocationResolverManager final : public Interface {
public:
    explicit LocationResolverManager(std::shared_ptr<ContentStore> store) : store_(std::move(store)) {}
    const char* Name() const override { return "lr"; }
    hk::Result Handle(const Request& request, Response& response) override {
        switch (request.command) {
        case 0: { // OpenLocationResolver(u8 storage) -> ILocationResolver
            Storage* storage = store_->Find(request.In<uint8_t>(0));
            if (!storage)
                return kUnknownStorage;
            response.objects.push_back(std::make_shared<LocationResolver>(*storage));
            return 0;
        }
        case 1: // OpenRegisteredLocationResolver -> IRegisteredLocationResolver
            response.objects.push_back(registered_);
            return 0;
        case 2: // RefreshLocationResolver(u8 storage)
            return store_->Find(request.In<uint8_t>(0)) ? 0 : kUnknownStorage;
        case 3: // OpenAddOnContentLocationResolver -> IAddOnContentLocationResolver
            response.objects.push_back(std::make_shared<AddOnContentLocationResolver>(*store_->Find(kBuiltInUser)));
            return 0;
        default:
            return kUnknown;
        }
    }

private:
    std::shared_ptr<ContentStore> store_;
    std::shared_ptr<RegisteredLocationResolver> registered_ = std::make_shared<RegisteredLocationResolver>();
};

} // namespace

void AddContentServices(NativeHost& host, const std::string& folder, bool trace) {
    (void)trace;
    auto store = std::make_shared<ContentStore>();
    store->Load(folder);
    host.Add("ncm", 16, [store] { return std::make_shared<ContentManager>(store); });
    host.Add("lr", 16, [store] { return std::make_shared<LocationResolverManager>(store); });
}

} // namespace services
