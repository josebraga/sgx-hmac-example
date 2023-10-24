#include "enclave_u.h"
#include "sgx_urts.h"

#include <iostream>
#include <string>

void ocall_print_string(const char* str)
{
  std::cout << str << std::endl;
}

int main() {
  sgx_enclave_id_t enclave_id;
  sgx_status_t sgx_status = sgx_create_enclave("libenclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);

  if (sgx_status != SGX_SUCCESS)
  {
    std::cerr << "unable to create enclave" << std::endl;
    return -1;
  }

  sgx_status_t status;
  sgx_status = ecall_hmac_test(enclave_id, &status);

  if (sgx_status != SGX_SUCCESS || status != SGX_SUCCESS) {
    std::cerr << "call failed, destroy" << std::endl;
    sgx_destroy_enclave(enclave_id);
    return -1;
  }
    
  sgx_destroy_enclave(enclave_id);
  return 0;
}
