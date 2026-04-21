/* Wrapper that exposes PBC inline/macro functions as regular C functions */
#include <pbc/pbc.h>
#include "bkem.h"

int himitsu_element_length_in_bytes(element_t e) {
    return element_length_in_bytes(e);
}

int himitsu_element_to_bytes(unsigned char *data, element_t e) {
    return element_to_bytes(data, e);
}

int himitsu_element_from_bytes(element_t e, unsigned char *data) {
    return element_from_bytes(e, data);
}

void himitsu_element_init_G1(element_t e, pairing_t pairing) {
    element_init_G1(e, pairing);
}

void himitsu_element_init_GT(element_t e, pairing_t pairing) {
    element_init_GT(e, pairing);
}

void himitsu_element_clear(element_t e) {
    element_clear(e);
}

int himitsu_element_cmp(element_t a, element_t b) {
    return element_cmp(a, b);
}
