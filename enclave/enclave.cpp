#include "enclave.h"
#include "enclave_t.h"

#include "../vendor/hmac_sha256/hmac_sha256.h"

#include <iomanip>
#include <string>
#include <vector>

std::string b2a_hex(char *byte_arr, int n)
{
    const static std::string hex_codes = "0123456789abcdef";
    std::string hex_string;
    for (int i = 0; i < n; ++i)
    {
        unsigned char bin_value = byte_arr[i];
        hex_string += hex_codes[(bin_value >> 4) & 0x0F];
        hex_string += hex_codes[bin_value & 0x0F];
    }
    return hex_string;
}

sgx_status_t ecall_hmac_test()
{
    const std::string api_key = "svq7Z9fAsTm2NAqH0B4V9ZrJGnHq0L7K";
    const std::string api_secret = "i6Mtd9qL00u6pE828itIX6VHJ711EDWX";

    std::string data_to_sign = "uRgdW4j3TX5mZ6Prq4m1dUG0K9unNoa1eWEIKgZ6Zz47F092T8zd5Atf8dj8j72c";

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(32);
    // Call hmac-sha256 function
    hmac_sha256(api_secret.data(),
                api_secret.size(),
                data_to_sign.data(),
                data_to_sign.size(),
                out.data(),
                out.size());

    std::string x_auth_signature = b2a_hex((char *)out.data(), (int)out.size());
    printf("Key: %s", api_secret.c_str());
    printf("Data: %s", data_to_sign.c_str());
    printf("Signature is: %s", x_auth_signature.c_str());
    return SGX_SUCCESS;
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
