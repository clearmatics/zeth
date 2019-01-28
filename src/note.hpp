#ifndef __ZETH_NOTE_HPP__
#define __ZETH_NOTE_HPP__

#include <array>
#include "bits256.hpp"

namespace libzeth {

class BaseNote {
protected:
    uint64_t value_ = 0;
public:
    BaseNote() {}
    BaseNote(uint64_t value) : value_(value) {};
    virtual ~BaseNote() {};

    inline uint64_t value() const { return value_; };
};

class ZethNote : public BaseNote {
public:
    bits256 a_pk; // 256-bit vector
    bits256 rho; // 256-bit vector
    bits256 r; // r is in theory a 384-bit random string. Here we take it as a random 256bit integer, that we use to generate a 384-bit string in the circuits
    bits256 cm; // 256-bit vector

    ZethNote(bits256 a_pk, uint64_t value, bits256 rho, bits256 r, bits256 cm)
        : BaseNote(value), a_pk(a_pk), rho(rho), r(r) , cm(cm){}

    ZethNote();
    virtual ~ZethNote() {};
};

} // libzeth

#endif // __ZETH_NOTE_HPP__