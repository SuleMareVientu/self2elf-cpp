#include <iostream>
#include <string>
#include <string_utils.h>
#include <fstream>
#include <aes.h>
#include <sce_types.h>
#include <miniz.h>
#include <self.h>

int string_to_byte_array(std::string str, std::uint32_t nBytes, unsigned char* dest)
{
    if (str.length() < nBytes * 2)
        return -1;

    for (std::uint32_t i = 0, j = 0; j < nBytes; i = i + 2, j++)
    {
        std::string byteString = str.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        dest[j] = byte;
    }
    return 0;
}

// Credits to TeamMolecule for their original work on this https://github.com/TeamMolecule/sceutils

void register_keys(KeyStore& SCE_KEYS, int type) {
    // case 0 registers external(retail), 1 registers internal proto keys, proto_keys not added.
    switch (type) {
    case 0:
        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SPKG,
            0,
            "2E6F4751D15B06C51F572A9306E52DD7007EA56A31D459EC6D3681AB08625501",
            "B3D541A568751DF8F4833BAB4EFE0537",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::NONE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SRVK,
            0,
            "4648164DB9E67009456C7CA6F2378835FD678539B36B3DE6F1C604B7D4258141",
            "6EC8AD67993DAE75675F0AFFDE5C41F3",
            0x10300000000,
            0x16920000000,
            SelfType::NONE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SRVK,
            0,
            "DAE4B0F901E338DEFF3CCDBDEA1E2FDEA9926BB98CB182443CC0C0F7FAE428EE",
            "18D925FA885C7E28A9CFF458C24D8BED",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::NONE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "9D4E4CE92EA1C4576EB9601EC43EC03AAE8EC324ECF6DE01E918E61D2223EE55",
            "CFEA3CCBA454D3279AD7CB0510431434",
            0x10300000000,
            0x16920000000,
            SelfType::SECURE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "B1B6FEB39A8BD7A2AC584D435E150C624F560D3EFB03E745C575E0844569E2D0",
            "89B4E6BAB03B03D49BF0FC927FEA8659",
            0x18000000000,
            0x36100000000,
            SelfType::SECURE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "59AC7F05E115D758201A3F3461BCA0D42BD186F00CFC24263973F622AD9ED30C",
            "A053B00BA4BF880799B4265C6BC064B5",
            0x36300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::SECURE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "7A7FB1560DCD121CEA5E11B90124B13282752F2D5B95D75036AB3A29BB3BD2AB",
            "6C71642A042A041F1EE3094070B009BE",
            0x10300000000,
            0x16920000000,
            SelfType::BOOT);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "B1B936B512F9A16E51B948622B26F15C53680C77AC332EC25846B839520393EC",
            "90D527BAF7296B5B6A576CFA6B54D266",
            0x18000000000,
            0x36100000000,
            SelfType::BOOT);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "426FD1D33FEBBFAC560B7957B94F445AE5F1DED2AA70F74DB944645DC439122F",
            "995F1364BB9735FA448B18D886150C85",
            0x36300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::BOOT);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "B4AAF62D48FBD898C240308A9773AFE57B8A18D783F0B37932BB21B51386A9A0",
            "8CD162C5C613376F3E4BEA0B8FD5A3D0",
            0x10300000000,
            0x16920000000,
            SelfType::KERNEL);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "849AF7E8DE5B9C28C38CA74963FCF155E0F200FB08185E46CDA87790AAA10D72",
            "88710E219454A3CBF6D382D4BBD22BFC",
            0x18000000000,
            0x36100000000,
            SelfType::KERNEL);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "18E26DF712C362769D4F5E70460D28D88B7B991733DE692C2B9463B41FF4B925",
            "5B13077EEA801FC77D492050801FA507",
            0x36300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::KERNEL);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "4769935C3B1CB248C3A88A406B1535D5DC2C0279D5901DE534DC4A11B8F60804",
            "0CE906F746D40105660456D827CEBD25",
            0x10300000000,
            0x16920000000,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "4769935C3B1CB248C3A88A406B1535D5DC2C0279D5901DE534DC4A11B8F60804",
            "0CE906F746D40105660456D827CEBD25",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "613AD6EAC63D4E14F51A8C6AF18C66621968323B6F205B5E515C16D77BB06671",
            "ADBDAA5041B2094CF2B359301DE64171",
            0x10300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            2,
            "0F2041269B26D6B7EF143E35E83E914629A92F50F3A4CEE14CDFF63AEC641117",
            "07EF64437F0CB6995E6D785E42796C83",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            3,
            "3AFADA34660C6515B539EBBBC79C9C0ADA4337C32652CA03C6DD21A1D612D8F4",
            "7F98A137869B91B1EB9604F81FD74C50",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            4,
            "8FF491B36713E8AA38DE30B303689657F07AE70A8A8B1D7867441C52DB39C806",
            "D9CC7E26CE99053E48F9BEF1CB93C184",
            0x36300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            5,
            "4D71B2FB3D4359FB34445305C88A5E82FA12D34A8308F312AA34B58F6112253A",
            "04A27133FF0205C96B7F45A60D7D417B",
            0x36300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::NPDRM,
            SceType::SELF,
            0,
            "C10368BF3D2943BC6E5BD05E46A9A7B6",
            "00000000000000000000000000000000",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::NPDRM,
            SceType::SELF,
            1,
            "16419DD3BFBE8BDC596929B72CE237CD",
            "00000000000000000000000000000000",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "AAA508FA5E85EAEE597ED2B27804D22287CFADF1DF32EDC7A7C58E8C9AA8BB36",
            "CD1BD3A59200CC67A3B804808DC2AE73",
            0x00000000000,
            0x16920000000,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "5661E5FB20CFD1D1DFF50C1E59A6EA977D0AA5C5770F53B9CDD4E9451FFF55CB",
            "23D02FF79BF430E2D123869BF0CACAA0",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "4181B2DF5F5D94D3C80B7D86EACF1928533A49BA58EDE2B43CDEE7E572568BD4",
            "B1678C0543B6C1997B63A6F4F3C8FD33",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            2,
            "5282582F17F068F89A260AAFB71C58928F45A8D08C681376B07FF9EAB1114226",
            "29672DF43E426F41AF46D42E8437D449",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            3,
            "270CBA370061B87077672ADB5142D18844AAED352A9CCEE63602B0D740594334",
            "1CF2454FBF47D76221B91AFC3B608C28",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            4,
            "A782BC5A9EDDFC49A513FF3E592C4677A8C8920F23C9F11F2558FB9D99A43868",
            "559B5E658559EB65EBF892C274E098A9",
            0x36300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            5,
            "12D64D0172495226010A687DE245A73DE028B3561E25E69BABC325636F3CAE0A",
            "F149EED1757E5A915B24309795BFC380",
            0x36300000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);
        break;
    case 1:
        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SPKG,
            0,
            "2E6F4751D15B06C51F572A9306E52DD7007EA56A31D459EC6D3681AB08625501",
            "B3D541A568751DF8F4833BAB4EFE0537",
            0x10400000000,
            0xFFF00000000,
            SelfType::NONE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SRVK,
            0,
            "4648164DB9E67009456C7CA6F2378835FD678539B36B3DE6F1C604B7D4258141",
            "6EC8AD67993DAE75675F0AFFDE5C41F3",
            0x10300000000,
            0x16920000000,
            SelfType::NONE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SRVK,
            0,
            "DAE4B0F901E338DEFF3CCDBDEA1E2FDEA9926BB98CB182443CC0C0F7FAE428EE",
            "18D925FA885C7E28A9CFF458C24D8BED",
            0x18000000000,
            0xFFF00000000,
            SelfType::NONE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "9D4E4CE92EA1C4576EB9601EC43EC03AAE8EC324ECF6DE01E918E61D2223EE55",
            "CFEA3CCBA454D3279AD7CB0510431434",
            0x10300000000,
            0x16920000000,
            SelfType::SECURE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "B1B6FEB39A8BD7A2AC584D435E150C624F560D3EFB03E745C575E0844569E2D0",
            "89B4E6BAB03B03D49BF0FC927FEA8659",
            0x18000000000,
            0x36100000000,
            SelfType::SECURE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "59AC7F05E115D758201A3F3461BCA0D42BD186F00CFC24263973F622AD9ED30C",
            "A053B00BA4BF880799B4265C6BC064B5",
            0x36300000000,
            0xFFF00000000,
            SelfType::SECURE);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "7A7FB1560DCD121CEA5E11B90124B13282752F2D5B95D75036AB3A29BB3BD2AB",
            "6C71642A042A041F1EE3094070B009BE",
            0x10300000000,
            0x18000000000,
            SelfType::BOOT);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "B1B936B512F9A16E51B948622B26F15C53680C77AC332EC25846B839520393EC",
            "90D527BAF7296B5B6A576CFA6B54D266",
            0x18000000000,
            0x36100000000,
            SelfType::BOOT);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "426FD1D33FEBBFAC560B7957B94F445AE5F1DED2AA70F74DB944645DC439122F",
            "995F1364BB9735FA448B18D886150C85",
            0x36300000000,
            0xFFF00000000,
            SelfType::BOOT);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "B4AAF62D48FBD898C240308A9773AFE57B8A18D783F0B37932BB21B51386A9A0",
            "8CD162C5C613376F3E4BEA0B8FD5A3D0",
            0x10300000000,
            0x16920000000,
            SelfType::KERNEL);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "849AF7E8DE5B9C28C38CA74963FCF155E0F200FB08185E46CDA87790AAA10D72",
            "88710E219454A3CBF6D382D4BBD22BFC",
            0x18000000000,
            0x36100000000,
            SelfType::KERNEL);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "18E26DF712C362769D4F5E70460D28D88B7B991733DE692C2B9463B41FF4B925",
            "5B13077EEA801FC77D492050801FA507",
            0x36300000000,
            0xFFF00000000,
            SelfType::KERNEL);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "4769935C3B1CB248C3A88A406B1535D5DC2C0279D5901DE534DC4A11B8F60804",
            "0CE906F746D40105660456D827CEBD25",
            0x10300000000,
            0x16920000000,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "4769935C3B1CB248C3A88A406B1535D5DC2C0279D5901DE534DC4A11B8F60804",
            "0CE906F746D40105660456D827CEBD25",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "613AD6EAC63D4E14F51A8C6AF18C66621968323B6F205B5E515C16D77BB06671",
            "ADBDAA5041B2094CF2B359301DE64171",
            0x00000000000,
            0xFFF00000000,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            2,
            "0F2041269B26D6B7EF143E35E83E914629A92F50F3A4CEE14CDFF63AEC641117",
            "07EF64437F0CB6995E6D785E42796C83",
            0x00000000000,
            0xFFF00000000,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            3,
            "3AFADA34660C6515B539EBBBC79C9C0ADA4337C32652CA03C6DD21A1D612D8F4",
            "7F98A137869B91B1EB9604F81FD74C50",
            0x00000000000,
            0xFFF00000000,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            4,
            "8FF491B36713E8AA38DE30B303689657F07AE70A8A8B1D7867441C52DB39C806",
            "D9CC7E26CE99053E48F9BEF1CB93C184",
            0x00000000000,
            0xFFF00000000,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            5,
            "4D71B2FB3D4359FB34445305C88A5E82FA12D34A8308F312AA34B58F6112253A",
            "04A27133FF0205C96B7F45A60D7D417B",
            0x00000000000,
            0xFFF00000000,
            SelfType::USER);

        SCE_KEYS.register_keys(
            KeyType::NPDRM,
            SceType::SELF,
            0,
            "C10368BF3D2943BC6E5BD05E46A9A7B6",
            "00000000000000000000000000000000",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::NPDRM,
            SceType::SELF,
            1,
            "16419DD3BFBE8BDC596929B72CE237CD",
            "00000000000000000000000000000000",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "AAA508FA5E85EAEE597ED2B27804D22287CFADF1DF32EDC7A7C58E8C9AA8BB36",
            "CD1BD3A59200CC67A3B804808DC2AE73",
            0x00000000000,
            0x16920000000,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            0,
            "5661E5FB20CFD1D1DFF50C1E59A6EA977D0AA5C5770F53B9CDD4E9451FFF55CB",
            "23D02FF79BF430E2D123869BF0CACAA0",
            0x18000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            1,
            "4181B2DF5F5D94D3C80B7D86EACF1928533A49BA58EDE2B43CDEE7E572568BD4",
            "B1678C0543B6C1997B63A6F4F3C8FD33",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            2,
            "5282582F17F068F89A260AAFB71C58928F45A8D08C681376B07FF9EAB1114226",
            "29672DF43E426F41AF46D42E8437D449",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            3,
            "270CBA370061B87077672ADB5142D18844AAED352A9CCEE63602B0D740594334",
            "1CF2454FBF47D76221B91AFC3B608C28",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            4,
            "A782BC5A9EDDFC49A513FF3E592C4677A8C8920F23C9F11F2558FB9D99A43868",
            "559B5E658559EB65EBF892C274E098A9",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);

        SCE_KEYS.register_keys(
            KeyType::METADATA,
            SceType::SELF,
            5,
            "12D64D0172495226010A687DE245A73DE028B3561E25E69BABC325636F3CAE0A",
            "F149EED1757E5A915B24309795BFC380",
            0x00000000000,
            0xFFFFFFFFFFFFFFFF,
            SelfType::APP);
        break;
    }
}

std::string decompress_segments(const std::vector<uint8_t>& decrypted_data, const uint64_t& size) {
    mz_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;
    if (mz_inflateInit(&stream) != MZ_OK) {
        fprintf(stderr, "Error: inflateInit failed while decompressing\n");
        return "";
    }

    const std::string compressed_data((char*)&decrypted_data[0], size);
    stream.next_in = (Bytef*)compressed_data.data();
    stream.avail_in = static_cast<unsigned int>(compressed_data.size());

    int ret = 0;
    char outbuffer[4096];
    std::string decompressed_data;

    do {
        stream.next_out = reinterpret_cast<Bytef*>(outbuffer);
        stream.avail_out = sizeof(outbuffer);

        ret = mz_inflate(&stream, 0);

        if (decompressed_data.size() < stream.total_out) {
            decompressed_data.append(outbuffer, stream.total_out - decompressed_data.size());
        }
    } while (ret == MZ_OK);

    mz_inflateEnd(&stream);

    if (ret != MZ_STREAM_END) {
        fprintf(stderr, "Error: Exception during zlib decompression: (%d) %s\n", ret, stream.msg);
        return "";
    }
    return decompressed_data;
}

void self2elf(const std::string& infile, const std::string& outfile, KeyStore& SCE_KEYS, unsigned char* klictxt) {
    std::ifstream filein(infile, std::ios::binary);
    std::ofstream fileout(outfile, std::ios::binary);

    int npdrmtype = 0;

    char sceheaderbuffer[SceHeader::Size];
    char selfheaderbuffer[SelfHeader::Size];
    char appinfobuffer[AppInfoHeader::Size];
    char verinfobuffer[SceVersionInfo::Size];
    char controlinfobuffer[SceControlInfo::Size];

    filein.read(sceheaderbuffer, SceHeader::Size);
    filein.read(selfheaderbuffer, SelfHeader::Size);

    const SceHeader sce_hdr = SceHeader(sceheaderbuffer);
    const SelfHeader self_hdr = SelfHeader(selfheaderbuffer);

    filein.seekg(self_hdr.appinfo_offset);
    filein.read(appinfobuffer, AppInfoHeader::Size);

    const AppInfoHeader appinfo_hdr = AppInfoHeader(appinfobuffer);

    filein.seekg(self_hdr.sceversion_offset);
    filein.read(verinfobuffer, SceVersionInfo::Size);

    const SceVersionInfo verinfo_hdr = SceVersionInfo(verinfobuffer);

    filein.seekg(self_hdr.controlinfo_offset);
    filein.read(controlinfobuffer, SceControlInfo::Size);

    SceControlInfo controlinfo_hdr = SceControlInfo(controlinfobuffer);
    auto ci_off = SceControlInfo::Size;

    if (controlinfo_hdr.type == ControlType::DIGEST_SHA256) {
        filein.seekg(self_hdr.controlinfo_offset + ci_off);
        ci_off += SceControlInfoDigest256::Size;
        char controldigest256buffer[SceControlInfoDigest256::Size];
        filein.read(controldigest256buffer, SceControlInfoDigest256::Size);
        const SceControlInfoDigest256 controldigest256 = SceControlInfoDigest256(controldigest256buffer);
    }
    filein.seekg(self_hdr.controlinfo_offset + ci_off);
    filein.read(controlinfobuffer, SceControlInfo::Size);
    controlinfo_hdr = SceControlInfo(controlinfobuffer);
    ci_off += SceControlInfo::Size;

    if (controlinfo_hdr.type == ControlType::NPDRM_VITA) {
        filein.seekg(self_hdr.controlinfo_offset + ci_off);
        ci_off += SceControlInfoDRM::Size;
        char controlnpdrmbuffer[SceControlInfoDRM::Size];
        filein.read(controlnpdrmbuffer, SceControlInfoDRM::Size);
        const SceControlInfoDRM controlnpdrm = SceControlInfoDRM(controlnpdrmbuffer);
        npdrmtype = controlnpdrm.npdrm_type;
    }

    filein.seekg(self_hdr.elf_offset);
    char dat[ElfHeader::Size];
    filein.read(dat, ElfHeader::Size);
    fileout.write(dat, ElfHeader::Size);

    const ElfHeader elf_hdr = ElfHeader(dat);
    std::vector<ElfPhdr> elf_phdrs;
    std::vector<SegmentInfo> segment_infos;
    bool encrypted = false;
    uint64_t at = ElfHeader::Size;

    for (uint16_t i = 0; i < elf_hdr.e_phnum; i++) {
        filein.seekg(self_hdr.phdr_offset + i * ElfPhdr::Size);
        char dat[ElfPhdr::Size];
        filein.read(dat, ElfPhdr::Size);
        const ElfPhdr phdr = ElfPhdr(dat);
        elf_phdrs.push_back(phdr);
        fileout.write(dat, ElfPhdr::Size);
        at += ElfPhdr::Size;

        filein.seekg(self_hdr.segment_info_offset + i * SegmentInfo::Size);
        char segmentinfobuffer[SegmentInfo::Size];
        filein.read(segmentinfobuffer, SegmentInfo::Size);
        const SegmentInfo segment_info = SegmentInfo(segmentinfobuffer);
        segment_infos.push_back(segment_info);

        if (segment_info.plaintext == SecureBool::NO)
            encrypted = true;
    }

    std::vector<SceSegment> scesegs;

    if (encrypted) {
        scesegs = get_segments(filein, sce_hdr, SCE_KEYS, appinfo_hdr.sys_version, appinfo_hdr.self_type, npdrmtype, klictxt);
    }

    for (uint16_t i = 0; i < elf_hdr.e_phnum; i++) {
        int idx = 0;

        if (!scesegs.empty())
            idx = scesegs[i].idx;
        else
            idx = i;
        if (elf_phdrs[idx].p_filesz == 0)
            continue;

        const uint64_t pad_len = elf_phdrs[idx].p_offset - at;
        if (pad_len < 0)
            fprintf(stderr, "Error: ELF p_offset Invalid\n");

        std::vector<char> padding;
        for (int i = 0; i < pad_len; i++) {
            padding.push_back('\0');
        }

        fileout.write(padding.data(), pad_len);

        at += pad_len;

        filein.seekg(segment_infos[idx].offset);
        std::vector<unsigned char> dat(segment_infos[idx].size);
        filein.read((char*)&dat[0], segment_infos[idx].size);

        std::vector<unsigned char> decrypted_data(segment_infos[idx].size);
        if (segment_infos[idx].plaintext == SecureBool::NO) {
            aes_context aes_ctx;
            aes_setkey_enc(&aes_ctx, (unsigned char*)scesegs[i].key.c_str(), 128);
            size_t ctr_nc_off = 0;
            unsigned char ctr_stream_block[0x10];
            aes_crypt_ctr(&aes_ctx, segment_infos[idx].size, &ctr_nc_off, (unsigned char*)scesegs[i].iv.c_str(), ctr_stream_block, &dat[0], &decrypted_data[0]);
        }

        if (segment_infos[idx].compressed == SecureBool::YES) {
            const std::string decompressed_data = decompress_segments(decrypted_data, segment_infos[idx].size);
            segment_infos[idx].compressed = SecureBool::NO;
            fileout.write(decompressed_data.c_str(), decompressed_data.length());
            at += decompressed_data.length();
        }
        else {
            fileout.write((char*)&decrypted_data[0], segment_infos[idx].size);
            at += segment_infos[idx].size;
        }
    }
    filein.close();
    fileout.close();
}

std::vector<SceSegment> get_segments(std::ifstream& file, const SceHeader& sce_hdr, KeyStore& SCE_KEYS, const uint64_t sysver, const SelfType self_type, int keytype, unsigned char* klictxt) {
    file.seekg(sce_hdr.metadata_offset + 48);
    std::vector<char> dat(sce_hdr.header_length - sce_hdr.metadata_offset - 48);
    file.read(&dat[0], sce_hdr.header_length - sce_hdr.metadata_offset - 48);

    const std::string key = SCE_KEYS.get(KeyType::METADATA, sce_hdr.sce_type, sysver, sce_hdr.key_revision, self_type).key;
    const std::string iv = SCE_KEYS.get(KeyType::METADATA, sce_hdr.sce_type, sysver, sce_hdr.key_revision, self_type).iv;
    aes_context aes_ctx;
    unsigned char dec_in[MetadataInfo::Size];

    if (self_type == SelfType::APP) {
        keytype = 0;
        if (sce_hdr.key_revision >= 2)
            keytype = 1;
        const std::string np_key = SCE_KEYS.get(KeyType::NPDRM, sce_hdr.sce_type, sysver, keytype, self_type).key;
        const std::string np_iv = SCE_KEYS.get(KeyType::NPDRM, sce_hdr.sce_type, sysver, keytype, self_type).iv;
        const auto np_key_vec = string_utils::string_to_byte_array(np_key);
        auto np_iv_vec = string_utils::string_to_byte_array(np_iv);
        auto np_key_bytes = &np_key_vec[0];
        auto np_iv_bytes = &np_iv_vec[0];
        unsigned char predec[16];
        aes_setkey_dec(&aes_ctx, np_key_bytes, 128);
        aes_crypt_cbc(&aes_ctx, AES_DECRYPT, 16, np_iv_bytes, klictxt, predec);

        unsigned char input_data[MetadataInfo::Size];
        std::copy(&dat[0], &dat[64], input_data);
        aes_setkey_dec(&aes_ctx, predec, 128);
        aes_crypt_cbc(&aes_ctx, AES_DECRYPT, MetadataInfo::Size, np_iv_bytes, input_data, dec_in);

    }
    else {
        std::copy(&dat[0], &dat[64], dec_in);
    }
    unsigned char dec[64];

    const auto key_vec = string_utils::string_to_byte_array(key);
    auto iv_vec = string_utils::string_to_byte_array(iv);
    auto key_bytes = &key_vec[0];
    auto iv_bytes = &iv_vec[0];
    aes_setkey_dec(&aes_ctx, key_bytes, 256);
    aes_crypt_cbc(&aes_ctx, AES_DECRYPT, 64, iv_bytes, dec_in, dec);

    MetadataInfo metadata_info = MetadataInfo((char*)dec);

    std::vector<unsigned char> dec1(sce_hdr.header_length - sce_hdr.metadata_offset - 48 - MetadataInfo::Size);
    std::vector<unsigned char> input_data(sce_hdr.header_length - sce_hdr.metadata_offset - 48 - MetadataInfo::Size);
    memcpy(&input_data[0], &dat[64], sce_hdr.header_length - sce_hdr.metadata_offset - 48 - MetadataInfo::Size);
    aes_setkey_dec(&aes_ctx, metadata_info.key, 128);
    aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sce_hdr.header_length - sce_hdr.metadata_offset - 48 - MetadataInfo::Size, metadata_info.iv, &input_data[0], &dec1[0]);

    unsigned char dec2[MetadataHeader::Size];
    std::copy(&dec1[0], &dec1[MetadataHeader::Size], dec2);
    MetadataHeader metadata_hdr = MetadataHeader((char*)dec2);

    std::vector<SceSegment> segs;
    const auto start = MetadataHeader::Size + metadata_hdr.section_count * MetadataSection::Size;
    std::vector<std::string> vault;

    for (uint32_t i = 0; i < metadata_hdr.key_count; i++) {
        std::string key(&dec1[0] + (start + (16 * i)), &dec1[0] + (start + (16 * (i + 1))));
        vault.push_back(key);
    }

    for (uint32_t i = 0; i < metadata_hdr.section_count; i++) {
        std::vector<unsigned char> dec3((MetadataHeader::Size + i * MetadataSection::Size + MetadataSection::Size) - (MetadataHeader::Size + i * MetadataSection::Size));
        memcpy(&dec3[0], &dec1[0] + (MetadataHeader::Size + i * MetadataSection::Size), (MetadataHeader::Size + i * MetadataSection::Size + MetadataSection::Size) - (MetadataHeader::Size + i * MetadataSection::Size));
        MetadataSection metsec = MetadataSection((char*)&dec3[0]);

        if (metsec.encryption == EncryptionType::AES128CTR) {
            segs.push_back({ metsec.offset, metsec.seg_idx, metsec.size, metsec.compression == CompressionType::DEFLATE, vault[metsec.key_idx], vault[metsec.iv_idx] });
        }
    }
    return segs;
}

void usage(const char** argv) {
    fprintf(stderr, "usage: %s input.self output.elf klicensee\n", argv[0] ? argv[0] : "self2elf");
    fprintf(stderr, "\tklicensee : Can be a path to a \"work.bin\" file or a hex coded string (e.g.: 00112233445566778899AABBCCDDEEFF).\n");
    exit(1);
}

int main(int argc, const char** argv)
{
    const char* input_path, * output_path, * klicense_arg;

    argc--;
    argv++; // strip first argument
    if (argc < 3)
        usage(argv);

    input_path = argv[0];
    output_path = argv[1];
    klicense_arg = argv[2];

    constexpr int klicense_size = 0x10;
    unsigned char klicense_buf[klicense_size];

    std::ifstream workbin(klicense_arg, std::ios::binary);
    if (workbin)
    {
        workbin.seekg(0x50, std::ios::beg);
        workbin.read(reinterpret_cast<char*>(klicense_buf), klicense_size);
        workbin.close();
    }
    else if (strlen(klicense_arg) == (klicense_size * 2))
    {
        if (string_to_byte_array(std::string(klicense_arg), klicense_size, klicense_buf) != 0)
        {
            fprintf(stderr, "Error: Input string is not a valid klicensee in HEX format\n");
            return 1;
        }

        /*
        std::stringstream str; std::string s1 = klicense_arg;
        str << s1; str >> std::hex >> klicense_buf;
        */
    }
    else
    {
        fprintf(stderr, "Error: No valid klicensee was provided\n");
        return 1;
    }

    KeyStore keys; register_keys(keys, 0);
    self2elf(input_path, output_path, keys, klicense_buf);
    return 0;
}
