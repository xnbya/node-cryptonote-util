#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_protocol/blobdatatype.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "common/base58.h"
#include "serialization/binary_utils.h"
#include <nan.h>

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
  free(data);
}

using namespace node;
using namespace v8;
using namespace cryptonote;

blobdata uint64be_to_blob(uint64_t num) {
    blobdata res = "        ";
    res[0] = num >> 56 & 0xff;
    res[1] = num >> 48 & 0xff;
    res[2] = num >> 40 & 0xff;
    res[3] = num >> 32 & 0xff;
    res[4] = num >> 24 & 0xff;
    res[5] = num >> 16 & 0xff;
    res[6] = num >> 8  & 0xff;
    res[7] = num       & 0xff;
    return res;
}

NAN_METHOD(convert_blob) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        return THROW_ERROR_EXCEPTION("Failed to parse block");

    output = get_block_hashing_blob(b);
    
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

void address_decode(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data))
    {
        info.GetReturnValue().Set(Nan::Undefined());
    }
    //    info.GetReturnValue().Set(Nan::Undefined());
    

    account_public_address adr;
    if (!::serialization::parse_binary(data, adr) || !crypto::check_key(adr.m_spend_public_key) || !crypto::check_key(adr.m_view_public_key))
    {
        if(data.length())
        {
            data = uint64be_to_blob(prefix) + data;
        }
        else
        {
            info.GetReturnValue().Set(Nan::Undefined());
        }
             v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)data.data(), data.size()).ToLocalChecked();
        info.GetReturnValue().Set(
            returnValue
         );

    }
    else
    {
        info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(prefix)));
    }
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("convert_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("address_decode").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode)).ToLocalChecked());
}

NODE_MODULE(cryptonote, init)
