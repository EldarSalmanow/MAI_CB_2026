#include <args.hxx>

#include <lab1/cipher_context.h>
#include <lab1/deal_algorithm.h>

#include <iostream>


using Block = std::array<std::uint8_t, 16>;

constexpr Block key{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
constexpr Block iv{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
constexpr std::uint64_t delta = 1;

struct Arguments {
    std::filesystem::path input;
    std::filesystem::path decrypted;
    std::filesystem::path intermediate;
    CipherMode mode = CipherMode::CBC;
    PaddingMode padding = PaddingMode::PKCS7;
    bool help = false;
};

class ArgumentParser {
public:
    static auto Parse(int argc, char** argv) -> Arguments {
        const auto required = args::Options::Required | args::Options::Single;

        args::ArgumentParser parser(
            "Encrypt a file with DEAL-128, then decrypt it.",
            "Stream modes ignore padding. Zeros padding is retained after decryption.");
        args::HelpFlag help(parser, "help", "Show this help.", {'h', "help"});
        args::ValueFlag<std::string> input(parser, "FILE", "Input file.", {"input"}, required);
        args::ValueFlag<std::string> decrypted(parser, "FILE", "Decrypted file.", {"decrypted"}, required);
        args::ValueFlag<std::string> intermediate(parser, "FILE", "Encrypted file.", {"intermediate"}, required);
        args::MapFlag<std::string, CipherMode> mode(
            parser, "MODE", "ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta.", {"mode"},
            {{"ECB", CipherMode::ECB}, {"CBC", CipherMode::CBC}, {"PCBC", CipherMode::PCBC},
             {"CFB", CipherMode::CFB}, {"OFB", CipherMode::OFB}, {"CTR", CipherMode::CTR},
             {"RandomDelta", CipherMode::RandomDelta}}, required);
        args::MapFlag<std::string, PaddingMode> padding(
            parser, "PADDING", "Zeros, ANSI_X923, PKCS7, ISO_10126.", {"padding"},
            {{"Zeros", PaddingMode::Zeros}, {"ANSI_X923", PaddingMode::ANSI_X923},
             {"PKCS7", PaddingMode::PKCS7}, {"ISO_10126", PaddingMode::ISO_10126}}, required);

        try {
            parser.ParseCLI(argc, argv);
        } catch (const args::Help&) {
            std::cout << parser;

            return {
                .help = true
            };
        }

        return {
            args::get(input),
            args::get(decrypted),
            args::get(intermediate),
            args::get(mode),
            args::get(padding)
        };
    }
};

int main(int argc, char* argv[]) {
    try {
        const auto args = ArgumentParser::Parse(argc, argv);

        if (args.help) {
            return 0;
        }

        CipherParams params;
        params.iv.assign(iv.begin(), iv.end());
        params.additional_args.emplace_back(delta);

        SymmetricCipherContext<DEALAlgorithm> context(key, args.mode, args.padding, params);

        context.EncryptFileAsync(args.input, args.intermediate).get();
        std::cout << "Encrypted: " << args.intermediate << std::endl;

        context.DecryptFileAsync(args.intermediate, args.decrypted).get();
        std::cout << "Decrypted: " << args.decrypted << std::endl;

        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << "\nUse --help for usage.\n";

        return 1;
    }
}
