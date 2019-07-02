#ifndef __ZETH_NOTE_HPP__
#define __ZETH_NOTE_HPP__

#include "snarks_alias.hpp"

namespace libzeth {

template<typename FieldT>
class BaseNote {
protected:
    FieldT value_ = FieldT("0");
public:
    BaseNote(){}
    BaseNote(FieldT value) : value_(value) {};
    virtual ~BaseNote() {};

    inline FieldT value() const { return value_; };

    // Test if the note is a 0-valued note
    inline bool is_zero_valued() const {
        return value_ == FieldT("0");
    }

};

template<typename FieldT>
class ZethNote : public BaseNote<FieldT> {
public:
    FieldT a_pk;
    FieldT rho;
    FieldT r;
    //FieldT cm;

    ZethNote(FieldT a_pk, FieldT value, FieldT rho, FieldT r/*, FieldT cm*/)
        : BaseNote<FieldT>(value), a_pk(a_pk), rho(rho), r(r)/*, cm(cm)*/{}

    ZethNote(){};
    virtual ~ZethNote() {};
};

} // libzeth

#endif // __ZETH_NOTE_HPP__
