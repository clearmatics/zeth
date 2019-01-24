#ifndef ZETH_NOTE_H_
#define ZETH_NOTE_H_

#include "uint256.h"

#include <array>
#include <boost/optional.hpp>

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
    uint256 a_pk;
    uint256 rho;
    uint256 r;
    uint256 cm;

    ZethNote(uint256 a_pk, uint64_t value, uint256 rho, uint256 r, uint256 cm)
        : BaseNote(value), a_pk(a_pk), rho(rho), r(r) , cm(cm){}

    ZethNote();
    virtual ~ZethNote() {};
};

}

#endif // ZETH_NOTE_H_
