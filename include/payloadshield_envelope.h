#ifndef PAYLOADSHIELD_ENVELOPE_H
#define PAYLOADSHIELD_ENVELOPE_H

#include "payloadshield_crypto.h"

int payloadshield_envelope_unwrap(const unsigned char *json, size_t json_len,
    payloadshield_buffer_t *encoded_payload);
int payloadshield_envelope_wrap(const unsigned char *encoded_payload,
    size_t encoded_payload_len, payloadshield_buffer_t *json);

int payloadshield_base64_encode_buffer(const unsigned char *input,
    size_t input_len, payloadshield_buffer_t *output);
int payloadshield_base64_decode_buffer(const unsigned char *input,
    size_t input_len, payloadshield_buffer_t *output);

#endif