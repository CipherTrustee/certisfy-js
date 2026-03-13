let export_asn1js;
let export_pvtsutils;
let export_bytestreamjs;
let export_pvutils;

(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
/*!
 * Copyright (c) 2014, GMO GlobalSign
 * Copyright (c) 2015-2022, Peculiar Ventures
 * All rights reserved.
 * 
 * Author 2014-2019, Yury Strozhevsky
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */

'use strict';

var pvtsutils = require('pvtsutils');
var pvutils = require('pvutils');

function _interopNamespaceDefault(e) {
  var n = Object.create(null);
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        var d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k]; }
        });
      }
    });
  }
  n.default = e;
  return Object.freeze(n);
}

var pvtsutils__namespace = /*#__PURE__*/_interopNamespaceDefault(pvtsutils);
var pvutils__namespace = /*#__PURE__*/_interopNamespaceDefault(pvutils);

function assertBigInt() {
    if (typeof BigInt === "undefined") {
        throw new Error("BigInt is not defined. Your environment doesn't implement BigInt.");
    }
}
function concat(buffers) {
    let outputLength = 0;
    let prevLength = 0;
    for (let i = 0; i < buffers.length; i++) {
        const buffer = buffers[i];
        outputLength += buffer.byteLength;
    }
    const retView = new Uint8Array(outputLength);
    for (let i = 0; i < buffers.length; i++) {
        const buffer = buffers[i];
        retView.set(new Uint8Array(buffer), prevLength);
        prevLength += buffer.byteLength;
    }
    return retView.buffer;
}
function checkBufferParams(baseBlock, inputBuffer, inputOffset, inputLength) {
    if (!(inputBuffer instanceof Uint8Array)) {
        baseBlock.error = "Wrong parameter: inputBuffer must be 'Uint8Array'";
        return false;
    }
    if (!inputBuffer.byteLength) {
        baseBlock.error = "Wrong parameter: inputBuffer has zero length";
        return false;
    }
    if (inputOffset < 0) {
        baseBlock.error = "Wrong parameter: inputOffset less than zero";
        return false;
    }
    if (inputLength < 0) {
        baseBlock.error = "Wrong parameter: inputLength less than zero";
        return false;
    }
    if ((inputBuffer.byteLength - inputOffset - inputLength) < 0) {
        baseBlock.error = "End of input reached before message was fully decoded (inconsistent offset and length values)";
        return false;
    }
    return true;
}

class ViewWriter {
    constructor() {
        this.items = [];
    }
    write(buf) {
        this.items.push(buf);
    }
    final() {
        return concat(this.items);
    }
}

const powers2 = [new Uint8Array([1])];
const digitsString = "0123456789";
const NAME = "name";
const VALUE_HEX_VIEW = "valueHexView";
const IS_HEX_ONLY = "isHexOnly";
const ID_BLOCK = "idBlock";
const TAG_CLASS = "tagClass";
const TAG_NUMBER = "tagNumber";
const IS_CONSTRUCTED = "isConstructed";
const FROM_BER = "fromBER";
const TO_BER = "toBER";
const LOCAL = "local";
const EMPTY_STRING = "";
const EMPTY_BUFFER = new ArrayBuffer(0);
const EMPTY_VIEW = new Uint8Array(0);
const END_OF_CONTENT_NAME = "EndOfContent";
const OCTET_STRING_NAME = "OCTET STRING";
const BIT_STRING_NAME = "BIT STRING";

function HexBlock(BaseClass) {
    var _a;
    return _a = class Some extends BaseClass {
            get valueHex() {
                return this.valueHexView.slice().buffer;
            }
            set valueHex(value) {
                this.valueHexView = new Uint8Array(value);
            }
            constructor(...args) {
                var _b;
                super(...args);
                const params = args[0] || {};
                this.isHexOnly = (_b = params.isHexOnly) !== null && _b !== void 0 ? _b : false;
                this.valueHexView = params.valueHex ? pvtsutils__namespace.BufferSourceConverter.toUint8Array(params.valueHex) : EMPTY_VIEW;
            }
            fromBER(inputBuffer, inputOffset, inputLength) {
                const view = inputBuffer instanceof ArrayBuffer ? new Uint8Array(inputBuffer) : inputBuffer;
                if (!checkBufferParams(this, view, inputOffset, inputLength)) {
                    return -1;
                }
                const endLength = inputOffset + inputLength;
                this.valueHexView = view.subarray(inputOffset, endLength);
                if (!this.valueHexView.length) {
                    this.warnings.push("Zero buffer length");
                    return inputOffset;
                }
                this.blockLength = inputLength;
                return endLength;
            }
            toBER(sizeOnly = false) {
                if (!this.isHexOnly) {
                    this.error = "Flag 'isHexOnly' is not set, abort";
                    return EMPTY_BUFFER;
                }
                if (sizeOnly) {
                    return new ArrayBuffer(this.valueHexView.byteLength);
                }
                return (this.valueHexView.byteLength === this.valueHexView.buffer.byteLength)
                    ? this.valueHexView.buffer
                    : this.valueHexView.slice().buffer;
            }
            toJSON() {
                return {
                    ...super.toJSON(),
                    isHexOnly: this.isHexOnly,
                    valueHex: pvtsutils__namespace.Convert.ToHex(this.valueHexView),
                };
            }
        },
        _a.NAME = "hexBlock",
        _a;
}

class LocalBaseBlock {
    static blockName() {
        return this.NAME;
    }
    get valueBeforeDecode() {
        return this.valueBeforeDecodeView.slice().buffer;
    }
    set valueBeforeDecode(value) {
        this.valueBeforeDecodeView = new Uint8Array(value);
    }
    constructor({ blockLength = 0, error = EMPTY_STRING, warnings = [], valueBeforeDecode = EMPTY_VIEW, } = {}) {
        this.blockLength = blockLength;
        this.error = error;
        this.warnings = warnings;
        this.valueBeforeDecodeView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(valueBeforeDecode);
    }
    toJSON() {
        return {
            blockName: this.constructor.NAME,
            blockLength: this.blockLength,
            error: this.error,
            warnings: this.warnings,
            valueBeforeDecode: pvtsutils__namespace.Convert.ToHex(this.valueBeforeDecodeView),
        };
    }
}
LocalBaseBlock.NAME = "baseBlock";

class ValueBlock extends LocalBaseBlock {
    fromBER(_inputBuffer, _inputOffset, _inputLength) {
        throw TypeError("User need to make a specific function in a class which extends 'ValueBlock'");
    }
    toBER(_sizeOnly, _writer) {
        throw TypeError("User need to make a specific function in a class which extends 'ValueBlock'");
    }
}
ValueBlock.NAME = "valueBlock";

class LocalIdentificationBlock extends HexBlock(LocalBaseBlock) {
    constructor({ idBlock = {} } = {}) {
        var _a, _b, _c, _d;
        super();
        if (idBlock) {
            this.isHexOnly = (_a = idBlock.isHexOnly) !== null && _a !== void 0 ? _a : false;
            this.valueHexView = idBlock.valueHex
                ? pvtsutils__namespace.BufferSourceConverter.toUint8Array(idBlock.valueHex)
                : EMPTY_VIEW;
            this.tagClass = (_b = idBlock.tagClass) !== null && _b !== void 0 ? _b : -1;
            this.tagNumber = (_c = idBlock.tagNumber) !== null && _c !== void 0 ? _c : -1;
            this.isConstructed = (_d = idBlock.isConstructed) !== null && _d !== void 0 ? _d : false;
        }
        else {
            this.tagClass = -1;
            this.tagNumber = -1;
            this.isConstructed = false;
        }
    }
    toBER(sizeOnly = false) {
        let firstOctet = 0;
        switch (this.tagClass) {
            case 1:
                firstOctet |= 0x00;
                break;
            case 2:
                firstOctet |= 0x40;
                break;
            case 3:
                firstOctet |= 0x80;
                break;
            case 4:
                firstOctet |= 0xC0;
                break;
            default:
                this.error = "Unknown tag class";
                return EMPTY_BUFFER;
        }
        if (this.isConstructed)
            firstOctet |= 0x20;
        if (this.tagNumber < 31 && !this.isHexOnly) {
            const retView = new Uint8Array(1);
            if (!sizeOnly) {
                let number = this.tagNumber;
                number &= 0x1F;
                firstOctet |= number;
                retView[0] = firstOctet;
            }
            return retView.buffer;
        }
        if (!this.isHexOnly) {
            const encodedBuf = pvutils__namespace.utilToBase(this.tagNumber, 7);
            const encodedView = new Uint8Array(encodedBuf);
            const size = encodedBuf.byteLength;
            const retView = new Uint8Array(size + 1);
            retView[0] = (firstOctet | 0x1F);
            if (!sizeOnly) {
                for (let i = 0; i < (size - 1); i++)
                    retView[i + 1] = encodedView[i] | 0x80;
                retView[size] = encodedView[size - 1];
            }
            return retView.buffer;
        }
        const retView = new Uint8Array(this.valueHexView.byteLength + 1);
        retView[0] = (firstOctet | 0x1F);
        if (!sizeOnly) {
            const curView = this.valueHexView;
            for (let i = 0; i < (curView.length - 1); i++)
                retView[i + 1] = curView[i] | 0x80;
            retView[this.valueHexView.byteLength] = curView[curView.length - 1];
        }
        return retView.buffer;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const inputView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        if (!checkBufferParams(this, inputView, inputOffset, inputLength)) {
            return -1;
        }
        const intBuffer = inputView.subarray(inputOffset, inputOffset + inputLength);
        if (intBuffer.length === 0) {
            this.error = "Zero buffer length";
            return -1;
        }
        const tagClassMask = intBuffer[0] & 0xC0;
        switch (tagClassMask) {
            case 0x00:
                this.tagClass = (1);
                break;
            case 0x40:
                this.tagClass = (2);
                break;
            case 0x80:
                this.tagClass = (3);
                break;
            case 0xC0:
                this.tagClass = (4);
                break;
            default:
                this.error = "Unknown tag class";
                return -1;
        }
        this.isConstructed = (intBuffer[0] & 0x20) === 0x20;
        this.isHexOnly = false;
        const tagNumberMask = intBuffer[0] & 0x1F;
        if (tagNumberMask !== 0x1F) {
            this.tagNumber = (tagNumberMask);
            this.blockLength = 1;
        }
        else {
            let count = 1;
            let intTagNumberBuffer = this.valueHexView = new Uint8Array(255);
            let tagNumberBufferMaxLength = 255;
            while (intBuffer[count] & 0x80) {
                intTagNumberBuffer[count - 1] = intBuffer[count] & 0x7F;
                count++;
                if (count >= intBuffer.length) {
                    this.error = "End of input reached before message was fully decoded";
                    return -1;
                }
                if (count === tagNumberBufferMaxLength) {
                    tagNumberBufferMaxLength += 255;
                    const tempBufferView = new Uint8Array(tagNumberBufferMaxLength);
                    for (let i = 0; i < intTagNumberBuffer.length; i++)
                        tempBufferView[i] = intTagNumberBuffer[i];
                    intTagNumberBuffer = this.valueHexView = new Uint8Array(tagNumberBufferMaxLength);
                }
            }
            this.blockLength = (count + 1);
            intTagNumberBuffer[count - 1] = intBuffer[count] & 0x7F;
            const tempBufferView = new Uint8Array(count);
            for (let i = 0; i < count; i++)
                tempBufferView[i] = intTagNumberBuffer[i];
            intTagNumberBuffer = this.valueHexView = new Uint8Array(count);
            intTagNumberBuffer.set(tempBufferView);
            if (this.blockLength <= 9)
                this.tagNumber = pvutils__namespace.utilFromBase(intTagNumberBuffer, 7);
            else {
                this.isHexOnly = true;
                this.warnings.push("Tag too long, represented as hex-coded");
            }
        }
        if (((this.tagClass === 1))
            && (this.isConstructed)) {
            switch (this.tagNumber) {
                case 1:
                case 2:
                case 5:
                case 6:
                case 9:
                case 13:
                case 14:
                case 23:
                case 24:
                case 31:
                case 32:
                case 33:
                case 34:
                    this.error = "Constructed encoding used for primitive type";
                    return -1;
            }
        }
        return (inputOffset + this.blockLength);
    }
    toJSON() {
        return {
            ...super.toJSON(),
            tagClass: this.tagClass,
            tagNumber: this.tagNumber,
            isConstructed: this.isConstructed,
        };
    }
}
LocalIdentificationBlock.NAME = "identificationBlock";

class LocalLengthBlock extends LocalBaseBlock {
    constructor({ lenBlock = {} } = {}) {
        var _a, _b, _c;
        super();
        this.isIndefiniteForm = (_a = lenBlock.isIndefiniteForm) !== null && _a !== void 0 ? _a : false;
        this.longFormUsed = (_b = lenBlock.longFormUsed) !== null && _b !== void 0 ? _b : false;
        this.length = (_c = lenBlock.length) !== null && _c !== void 0 ? _c : 0;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const view = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        if (!checkBufferParams(this, view, inputOffset, inputLength)) {
            return -1;
        }
        const intBuffer = view.subarray(inputOffset, inputOffset + inputLength);
        if (intBuffer.length === 0) {
            this.error = "Zero buffer length";
            return -1;
        }
        if (intBuffer[0] === 0xFF) {
            this.error = "Length block 0xFF is reserved by standard";
            return -1;
        }
        this.isIndefiniteForm = intBuffer[0] === 0x80;
        if (this.isIndefiniteForm) {
            this.blockLength = 1;
            return (inputOffset + this.blockLength);
        }
        this.longFormUsed = !!(intBuffer[0] & 0x80);
        if (this.longFormUsed === false) {
            this.length = (intBuffer[0]);
            this.blockLength = 1;
            return (inputOffset + this.blockLength);
        }
        const count = intBuffer[0] & 0x7F;
        if (count > 8) {
            this.error = "Too big integer";
            return -1;
        }
        if ((count + 1) > intBuffer.length) {
            this.error = "End of input reached before message was fully decoded";
            return -1;
        }
        const lenOffset = inputOffset + 1;
        const lengthBufferView = view.subarray(lenOffset, lenOffset + count);
        if (lengthBufferView[count - 1] === 0x00)
            this.warnings.push("Needlessly long encoded length");
        this.length = pvutils__namespace.utilFromBase(lengthBufferView, 8);
        if (this.longFormUsed && (this.length <= 127))
            this.warnings.push("Unnecessary usage of long length form");
        this.blockLength = count + 1;
        return (inputOffset + this.blockLength);
    }
    toBER(sizeOnly = false) {
        let retBuf;
        let retView;
        if (this.length > 127)
            this.longFormUsed = true;
        if (this.isIndefiniteForm) {
            retBuf = new ArrayBuffer(1);
            if (sizeOnly === false) {
                retView = new Uint8Array(retBuf);
                retView[0] = 0x80;
            }
            return retBuf;
        }
        if (this.longFormUsed) {
            const encodedBuf = pvutils__namespace.utilToBase(this.length, 8);
            if (encodedBuf.byteLength > 127) {
                this.error = "Too big length";
                return (EMPTY_BUFFER);
            }
            retBuf = new ArrayBuffer(encodedBuf.byteLength + 1);
            if (sizeOnly)
                return retBuf;
            const encodedView = new Uint8Array(encodedBuf);
            retView = new Uint8Array(retBuf);
            retView[0] = encodedBuf.byteLength | 0x80;
            for (let i = 0; i < encodedBuf.byteLength; i++)
                retView[i + 1] = encodedView[i];
            return retBuf;
        }
        retBuf = new ArrayBuffer(1);
        if (sizeOnly === false) {
            retView = new Uint8Array(retBuf);
            retView[0] = this.length;
        }
        return retBuf;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            isIndefiniteForm: this.isIndefiniteForm,
            longFormUsed: this.longFormUsed,
            length: this.length,
        };
    }
}
LocalLengthBlock.NAME = "lengthBlock";

const typeStore = {};

class BaseBlock extends LocalBaseBlock {
    constructor({ name = EMPTY_STRING, optional = false, primitiveSchema, ...parameters } = {}, valueBlockType) {
        super(parameters);
        this.name = name;
        this.optional = optional;
        if (primitiveSchema) {
            this.primitiveSchema = primitiveSchema;
        }
        this.idBlock = new LocalIdentificationBlock(parameters);
        this.lenBlock = new LocalLengthBlock(parameters);
        this.valueBlock = valueBlockType ? new valueBlockType(parameters) : new ValueBlock(parameters);
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm)
            ? inputLength
            : this.lenBlock.length);
        if (resultOffset === -1) {
            this.error = this.valueBlock.error;
            return resultOffset;
        }
        if (!this.idBlock.error.length)
            this.blockLength += this.idBlock.blockLength;
        if (!this.lenBlock.error.length)
            this.blockLength += this.lenBlock.blockLength;
        if (!this.valueBlock.error.length)
            this.blockLength += this.valueBlock.blockLength;
        return resultOffset;
    }
    toBER(sizeOnly, writer) {
        const _writer = writer || new ViewWriter();
        if (!writer) {
            prepareIndefiniteForm(this);
        }
        const idBlockBuf = this.idBlock.toBER(sizeOnly);
        _writer.write(idBlockBuf);
        if (this.lenBlock.isIndefiniteForm) {
            _writer.write(new Uint8Array([0x80]).buffer);
            this.valueBlock.toBER(sizeOnly, _writer);
            _writer.write(new ArrayBuffer(2));
        }
        else {
            const valueBlockBuf = this.valueBlock.toBER(sizeOnly);
            this.lenBlock.length = valueBlockBuf.byteLength;
            const lenBlockBuf = this.lenBlock.toBER(sizeOnly);
            _writer.write(lenBlockBuf);
            _writer.write(valueBlockBuf);
        }
        if (!writer) {
            return _writer.final();
        }
        return EMPTY_BUFFER;
    }
    toJSON() {
        const object = {
            ...super.toJSON(),
            idBlock: this.idBlock.toJSON(),
            lenBlock: this.lenBlock.toJSON(),
            valueBlock: this.valueBlock.toJSON(),
            name: this.name,
            optional: this.optional,
        };
        if (this.primitiveSchema)
            object.primitiveSchema = this.primitiveSchema.toJSON();
        return object;
    }
    toString(encoding = "ascii") {
        if (encoding === "ascii") {
            return this.onAsciiEncoding();
        }
        return pvtsutils__namespace.Convert.ToHex(this.toBER());
    }
    onAsciiEncoding() {
        const name = this.constructor.NAME;
        const value = pvtsutils__namespace.Convert.ToHex(this.valueBlock.valueBeforeDecodeView);
        return `${name} : ${value}`;
    }
    isEqual(other) {
        if (this === other) {
            return true;
        }
        if (!(other instanceof this.constructor)) {
            return false;
        }
        const thisRaw = this.toBER();
        const otherRaw = other.toBER();
        return pvutils__namespace.isEqualBuffer(thisRaw, otherRaw);
    }
}
BaseBlock.NAME = "BaseBlock";
function prepareIndefiniteForm(baseBlock) {
    var _a;
    if (baseBlock instanceof typeStore.Constructed) {
        for (const value of baseBlock.valueBlock.value) {
            if (prepareIndefiniteForm(value)) {
                baseBlock.lenBlock.isIndefiniteForm = true;
            }
        }
    }
    return !!((_a = baseBlock.lenBlock) === null || _a === void 0 ? void 0 : _a.isIndefiniteForm);
}

class BaseStringBlock extends BaseBlock {
    getValue() {
        return this.valueBlock.value;
    }
    setValue(value) {
        this.valueBlock.value = value;
    }
    constructor({ value = EMPTY_STRING, ...parameters } = {}, stringValueBlockType) {
        super(parameters, stringValueBlockType);
        if (value) {
            this.fromString(value);
        }
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm)
            ? inputLength
            : this.lenBlock.length);
        if (resultOffset === -1) {
            this.error = this.valueBlock.error;
            return resultOffset;
        }
        this.fromBuffer(this.valueBlock.valueHexView);
        if (!this.idBlock.error.length)
            this.blockLength += this.idBlock.blockLength;
        if (!this.lenBlock.error.length)
            this.blockLength += this.lenBlock.blockLength;
        if (!this.valueBlock.error.length)
            this.blockLength += this.valueBlock.blockLength;
        return resultOffset;
    }
    onAsciiEncoding() {
        return `${this.constructor.NAME} : '${this.valueBlock.value}'`;
    }
}
BaseStringBlock.NAME = "BaseStringBlock";

class LocalPrimitiveValueBlock extends HexBlock(ValueBlock) {
    constructor({ isHexOnly = true, ...parameters } = {}) {
        super(parameters);
        this.isHexOnly = isHexOnly;
    }
}
LocalPrimitiveValueBlock.NAME = "PrimitiveValueBlock";

var _a$w;
class Primitive extends BaseBlock {
    constructor(parameters = {}) {
        super(parameters, LocalPrimitiveValueBlock);
        this.idBlock.isConstructed = false;
    }
}
_a$w = Primitive;
(() => {
    typeStore.Primitive = _a$w;
})();
Primitive.NAME = "PRIMITIVE";

function localChangeType(inputObject, newType) {
    if (inputObject instanceof newType) {
        return inputObject;
    }
    const newObject = new newType();
    newObject.idBlock = inputObject.idBlock;
    newObject.lenBlock = inputObject.lenBlock;
    newObject.warnings = inputObject.warnings;
    newObject.valueBeforeDecodeView = inputObject.valueBeforeDecodeView;
    return newObject;
}
function localFromBER(inputBuffer, inputOffset = 0, inputLength = inputBuffer.length) {
    const incomingOffset = inputOffset;
    let returnObject = new BaseBlock({}, ValueBlock);
    const baseBlock = new LocalBaseBlock();
    if (!checkBufferParams(baseBlock, inputBuffer, inputOffset, inputLength)) {
        returnObject.error = baseBlock.error;
        return {
            offset: -1,
            result: returnObject,
        };
    }
    const intBuffer = inputBuffer.subarray(inputOffset, inputOffset + inputLength);
    if (!intBuffer.length) {
        returnObject.error = "Zero buffer length";
        return {
            offset: -1,
            result: returnObject,
        };
    }
    let resultOffset = returnObject.idBlock.fromBER(inputBuffer, inputOffset, inputLength);
    if (returnObject.idBlock.warnings.length) {
        returnObject.warnings.concat(returnObject.idBlock.warnings);
    }
    if (resultOffset === -1) {
        returnObject.error = returnObject.idBlock.error;
        return {
            offset: -1,
            result: returnObject,
        };
    }
    inputOffset = resultOffset;
    inputLength -= returnObject.idBlock.blockLength;
    resultOffset = returnObject.lenBlock.fromBER(inputBuffer, inputOffset, inputLength);
    if (returnObject.lenBlock.warnings.length) {
        returnObject.warnings.concat(returnObject.lenBlock.warnings);
    }
    if (resultOffset === -1) {
        returnObject.error = returnObject.lenBlock.error;
        return {
            offset: -1,
            result: returnObject,
        };
    }
    inputOffset = resultOffset;
    inputLength -= returnObject.lenBlock.blockLength;
    if (!returnObject.idBlock.isConstructed
        && returnObject.lenBlock.isIndefiniteForm) {
        returnObject.error = "Indefinite length form used for primitive encoding form";
        return {
            offset: -1,
            result: returnObject,
        };
    }
    let newASN1Type = BaseBlock;
    switch (returnObject.idBlock.tagClass) {
        case 1:
            if ((returnObject.idBlock.tagNumber >= 37)
                && (returnObject.idBlock.isHexOnly === false)) {
                returnObject.error = "UNIVERSAL 37 and upper tags are reserved by ASN.1 standard";
                return {
                    offset: -1,
                    result: returnObject,
                };
            }
            switch (returnObject.idBlock.tagNumber) {
                case 0:
                    if ((returnObject.idBlock.isConstructed)
                        && (returnObject.lenBlock.length > 0)) {
                        returnObject.error = "Type [UNIVERSAL 0] is reserved";
                        return {
                            offset: -1,
                            result: returnObject,
                        };
                    }
                    newASN1Type = typeStore.EndOfContent;
                    break;
                case 1:
                    newASN1Type = typeStore.Boolean;
                    break;
                case 2:
                    newASN1Type = typeStore.Integer;
                    break;
                case 3:
                    newASN1Type = typeStore.BitString;
                    break;
                case 4:
                    newASN1Type = typeStore.OctetString;
                    break;
                case 5:
                    newASN1Type = typeStore.Null;
                    break;
                case 6:
                    newASN1Type = typeStore.ObjectIdentifier;
                    break;
                case 10:
                    newASN1Type = typeStore.Enumerated;
                    break;
                case 12:
                    newASN1Type = typeStore.Utf8String;
                    break;
                case 13:
                    newASN1Type = typeStore.RelativeObjectIdentifier;
                    break;
                case 14:
                    newASN1Type = typeStore.TIME;
                    break;
                case 15:
                    returnObject.error = "[UNIVERSAL 15] is reserved by ASN.1 standard";
                    return {
                        offset: -1,
                        result: returnObject,
                    };
                case 16:
                    newASN1Type = typeStore.Sequence;
                    break;
                case 17:
                    newASN1Type = typeStore.Set;
                    break;
                case 18:
                    newASN1Type = typeStore.NumericString;
                    break;
                case 19:
                    newASN1Type = typeStore.PrintableString;
                    break;
                case 20:
                    newASN1Type = typeStore.TeletexString;
                    break;
                case 21:
                    newASN1Type = typeStore.VideotexString;
                    break;
                case 22:
                    newASN1Type = typeStore.IA5String;
                    break;
                case 23:
                    newASN1Type = typeStore.UTCTime;
                    break;
                case 24:
                    newASN1Type = typeStore.GeneralizedTime;
                    break;
                case 25:
                    newASN1Type = typeStore.GraphicString;
                    break;
                case 26:
                    newASN1Type = typeStore.VisibleString;
                    break;
                case 27:
                    newASN1Type = typeStore.GeneralString;
                    break;
                case 28:
                    newASN1Type = typeStore.UniversalString;
                    break;
                case 29:
                    newASN1Type = typeStore.CharacterString;
                    break;
                case 30:
                    newASN1Type = typeStore.BmpString;
                    break;
                case 31:
                    newASN1Type = typeStore.DATE;
                    break;
                case 32:
                    newASN1Type = typeStore.TimeOfDay;
                    break;
                case 33:
                    newASN1Type = typeStore.DateTime;
                    break;
                case 34:
                    newASN1Type = typeStore.Duration;
                    break;
                default: {
                    const newObject = returnObject.idBlock.isConstructed
                        ? new typeStore.Constructed()
                        : new typeStore.Primitive();
                    newObject.idBlock = returnObject.idBlock;
                    newObject.lenBlock = returnObject.lenBlock;
                    newObject.warnings = returnObject.warnings;
                    returnObject = newObject;
                }
            }
            break;
        case 2:
        case 3:
        case 4:
        default: {
            newASN1Type = returnObject.idBlock.isConstructed
                ? typeStore.Constructed
                : typeStore.Primitive;
        }
    }
    returnObject = localChangeType(returnObject, newASN1Type);
    resultOffset = returnObject.fromBER(inputBuffer, inputOffset, returnObject.lenBlock.isIndefiniteForm ? inputLength : returnObject.lenBlock.length);
    returnObject.valueBeforeDecodeView = inputBuffer.subarray(incomingOffset, incomingOffset + returnObject.blockLength);
    return {
        offset: resultOffset,
        result: returnObject,
    };
}
function fromBER(inputBuffer) {
    if (!inputBuffer.byteLength) {
        const result = new BaseBlock({}, ValueBlock);
        result.error = "Input buffer has zero length";
        return {
            offset: -1,
            result,
        };
    }
    return localFromBER(pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer).slice(), 0, inputBuffer.byteLength);
}

function checkLen(indefiniteLength, length) {
    if (indefiniteLength) {
        return 1;
    }
    return length;
}
class LocalConstructedValueBlock extends ValueBlock {
    constructor({ value = [], isIndefiniteForm = false, ...parameters } = {}) {
        super(parameters);
        this.value = value;
        this.isIndefiniteForm = isIndefiniteForm;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const view = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        if (!checkBufferParams(this, view, inputOffset, inputLength)) {
            return -1;
        }
        this.valueBeforeDecodeView = view.subarray(inputOffset, inputOffset + inputLength);
        if (this.valueBeforeDecodeView.length === 0) {
            this.warnings.push("Zero buffer length");
            return inputOffset;
        }
        let currentOffset = inputOffset;
        while (checkLen(this.isIndefiniteForm, inputLength) > 0) {
            const returnObject = localFromBER(view, currentOffset, inputLength);
            if (returnObject.offset === -1) {
                this.error = returnObject.result.error;
                this.warnings.concat(returnObject.result.warnings);
                return -1;
            }
            currentOffset = returnObject.offset;
            this.blockLength += returnObject.result.blockLength;
            inputLength -= returnObject.result.blockLength;
            this.value.push(returnObject.result);
            if (this.isIndefiniteForm && returnObject.result.constructor.NAME === END_OF_CONTENT_NAME) {
                break;
            }
        }
        if (this.isIndefiniteForm) {
            if (this.value[this.value.length - 1].constructor.NAME === END_OF_CONTENT_NAME) {
                this.value.pop();
            }
            else {
                this.warnings.push("No EndOfContent block encoded");
            }
        }
        return currentOffset;
    }
    toBER(sizeOnly, writer) {
        const _writer = writer || new ViewWriter();
        for (let i = 0; i < this.value.length; i++) {
            this.value[i].toBER(sizeOnly, _writer);
        }
        if (!writer) {
            return _writer.final();
        }
        return EMPTY_BUFFER;
    }
    toJSON() {
        const object = {
            ...super.toJSON(),
            isIndefiniteForm: this.isIndefiniteForm,
            value: [],
        };
        for (const value of this.value) {
            object.value.push(value.toJSON());
        }
        return object;
    }
}
LocalConstructedValueBlock.NAME = "ConstructedValueBlock";

var _a$v;
class Constructed extends BaseBlock {
    constructor(parameters = {}) {
        super(parameters, LocalConstructedValueBlock);
        this.idBlock.isConstructed = true;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;
        const resultOffset = this.valueBlock.fromBER(inputBuffer, inputOffset, (this.lenBlock.isIndefiniteForm) ? inputLength : this.lenBlock.length);
        if (resultOffset === -1) {
            this.error = this.valueBlock.error;
            return resultOffset;
        }
        if (!this.idBlock.error.length)
            this.blockLength += this.idBlock.blockLength;
        if (!this.lenBlock.error.length)
            this.blockLength += this.lenBlock.blockLength;
        if (!this.valueBlock.error.length)
            this.blockLength += this.valueBlock.blockLength;
        return resultOffset;
    }
    onAsciiEncoding() {
        const values = [];
        for (const value of this.valueBlock.value) {
            values.push(value.toString("ascii").split("\n").map((o) => `  ${o}`).join("\n"));
        }
        const blockName = this.idBlock.tagClass === 3
            ? `[${this.idBlock.tagNumber}]`
            : this.constructor.NAME;
        return values.length
            ? `${blockName} :\n${values.join("\n")}`
            : `${blockName} :`;
    }
}
_a$v = Constructed;
(() => {
    typeStore.Constructed = _a$v;
})();
Constructed.NAME = "CONSTRUCTED";

class LocalEndOfContentValueBlock extends ValueBlock {
    fromBER(inputBuffer, inputOffset, _inputLength) {
        return inputOffset;
    }
    toBER(_sizeOnly) {
        return EMPTY_BUFFER;
    }
}
LocalEndOfContentValueBlock.override = "EndOfContentValueBlock";

var _a$u;
class EndOfContent extends BaseBlock {
    constructor(parameters = {}) {
        super(parameters, LocalEndOfContentValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 0;
    }
}
_a$u = EndOfContent;
(() => {
    typeStore.EndOfContent = _a$u;
})();
EndOfContent.NAME = END_OF_CONTENT_NAME;

var _a$t;
class Null extends BaseBlock {
    constructor(parameters = {}) {
        super(parameters, ValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 5;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        if (this.lenBlock.length > 0)
            this.warnings.push("Non-zero length of value block for Null type");
        if (!this.idBlock.error.length)
            this.blockLength += this.idBlock.blockLength;
        if (!this.lenBlock.error.length)
            this.blockLength += this.lenBlock.blockLength;
        this.blockLength += inputLength;
        if ((inputOffset + inputLength) > inputBuffer.byteLength) {
            this.error = "End of input reached before message was fully decoded (inconsistent offset and length values)";
            return -1;
        }
        return (inputOffset + inputLength);
    }
    toBER(sizeOnly, writer) {
        const retBuf = new ArrayBuffer(2);
        if (!sizeOnly) {
            const retView = new Uint8Array(retBuf);
            retView[0] = 0x05;
            retView[1] = 0x00;
        }
        if (writer) {
            writer.write(retBuf);
        }
        return retBuf;
    }
    onAsciiEncoding() {
        return `${this.constructor.NAME}`;
    }
}
_a$t = Null;
(() => {
    typeStore.Null = _a$t;
})();
Null.NAME = "NULL";

class LocalBooleanValueBlock extends HexBlock(ValueBlock) {
    get value() {
        for (const octet of this.valueHexView) {
            if (octet > 0) {
                return true;
            }
        }
        return false;
    }
    set value(value) {
        this.valueHexView[0] = value ? 0xFF : 0x00;
    }
    constructor({ value, ...parameters } = {}) {
        super(parameters);
        if (parameters.valueHex) {
            this.valueHexView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(parameters.valueHex);
        }
        else {
            this.valueHexView = new Uint8Array(1);
        }
        if (value) {
            this.value = value;
        }
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const inputView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        if (!checkBufferParams(this, inputView, inputOffset, inputLength)) {
            return -1;
        }
        this.valueHexView = inputView.subarray(inputOffset, inputOffset + inputLength);
        if (inputLength > 1)
            this.warnings.push("Boolean value encoded in more then 1 octet");
        this.isHexOnly = true;
        pvutils__namespace.utilDecodeTC.call(this);
        this.blockLength = inputLength;
        return (inputOffset + inputLength);
    }
    toBER() {
        return this.valueHexView.slice();
    }
    toJSON() {
        return {
            ...super.toJSON(),
            value: this.value,
        };
    }
}
LocalBooleanValueBlock.NAME = "BooleanValueBlock";

var _a$s;
class Boolean extends BaseBlock {
    getValue() {
        return this.valueBlock.value;
    }
    setValue(value) {
        this.valueBlock.value = value;
    }
    constructor(parameters = {}) {
        super(parameters, LocalBooleanValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 1;
    }
    onAsciiEncoding() {
        return `${this.constructor.NAME} : ${this.getValue}`;
    }
}
_a$s = Boolean;
(() => {
    typeStore.Boolean = _a$s;
})();
Boolean.NAME = "BOOLEAN";

class LocalOctetStringValueBlock extends HexBlock(LocalConstructedValueBlock) {
    constructor({ isConstructed = false, ...parameters } = {}) {
        super(parameters);
        this.isConstructed = isConstructed;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        let resultOffset = 0;
        if (this.isConstructed) {
            this.isHexOnly = false;
            resultOffset = LocalConstructedValueBlock.prototype.fromBER.call(this, inputBuffer, inputOffset, inputLength);
            if (resultOffset === -1)
                return resultOffset;
            for (let i = 0; i < this.value.length; i++) {
                const currentBlockName = this.value[i].constructor.NAME;
                if (currentBlockName === END_OF_CONTENT_NAME) {
                    if (this.isIndefiniteForm)
                        break;
                    else {
                        this.error = "EndOfContent is unexpected, OCTET STRING may consists of OCTET STRINGs only";
                        return -1;
                    }
                }
                if (currentBlockName !== OCTET_STRING_NAME) {
                    this.error = "OCTET STRING may consists of OCTET STRINGs only";
                    return -1;
                }
            }
        }
        else {
            this.isHexOnly = true;
            resultOffset = super.fromBER(inputBuffer, inputOffset, inputLength);
            this.blockLength = inputLength;
        }
        return resultOffset;
    }
    toBER(sizeOnly, writer) {
        if (this.isConstructed)
            return LocalConstructedValueBlock.prototype.toBER.call(this, sizeOnly, writer);
        return sizeOnly
            ? new ArrayBuffer(this.valueHexView.byteLength)
            : this.valueHexView.slice().buffer;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            isConstructed: this.isConstructed,
        };
    }
}
LocalOctetStringValueBlock.NAME = "OctetStringValueBlock";

var _a$r;
class OctetString extends BaseBlock {
    constructor({ idBlock = {}, lenBlock = {}, ...parameters } = {}) {
        var _b, _c;
        (_b = parameters.isConstructed) !== null && _b !== void 0 ? _b : (parameters.isConstructed = !!((_c = parameters.value) === null || _c === void 0 ? void 0 : _c.length));
        super({
            idBlock: {
                isConstructed: parameters.isConstructed,
                ...idBlock,
            },
            lenBlock: {
                ...lenBlock,
                isIndefiniteForm: !!parameters.isIndefiniteForm,
            },
            ...parameters,
        }, LocalOctetStringValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 4;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        this.valueBlock.isConstructed = this.idBlock.isConstructed;
        this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;
        if (inputLength === 0) {
            if (this.idBlock.error.length === 0)
                this.blockLength += this.idBlock.blockLength;
            if (this.lenBlock.error.length === 0)
                this.blockLength += this.lenBlock.blockLength;
            return inputOffset;
        }
        if (!this.valueBlock.isConstructed) {
            const view = inputBuffer instanceof ArrayBuffer ? new Uint8Array(inputBuffer) : inputBuffer;
            const buf = view.subarray(inputOffset, inputOffset + inputLength);
            try {
                if (buf.byteLength) {
                    const asn = localFromBER(buf, 0, buf.byteLength);
                    if (asn.offset !== -1 && asn.offset === inputLength) {
                        this.valueBlock.value = [asn.result];
                    }
                }
            }
            catch {
            }
        }
        return super.fromBER(inputBuffer, inputOffset, inputLength);
    }
    onAsciiEncoding() {
        if (this.valueBlock.isConstructed || (this.valueBlock.value && this.valueBlock.value.length)) {
            return Constructed.prototype.onAsciiEncoding.call(this);
        }
        const name = this.constructor.NAME;
        const value = pvtsutils__namespace.Convert.ToHex(this.valueBlock.valueHexView);
        return `${name} : ${value}`;
    }
    getValue() {
        if (!this.idBlock.isConstructed) {
            return this.valueBlock.valueHexView.slice().buffer;
        }
        const array = [];
        for (const content of this.valueBlock.value) {
            if (content instanceof _a$r) {
                array.push(content.valueBlock.valueHexView);
            }
        }
        return pvtsutils__namespace.BufferSourceConverter.concat(array);
    }
}
_a$r = OctetString;
(() => {
    typeStore.OctetString = _a$r;
})();
OctetString.NAME = OCTET_STRING_NAME;

class LocalBitStringValueBlock extends HexBlock(LocalConstructedValueBlock) {
    constructor({ unusedBits = 0, isConstructed = false, ...parameters } = {}) {
        super(parameters);
        this.unusedBits = unusedBits;
        this.isConstructed = isConstructed;
        this.blockLength = this.valueHexView.byteLength;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        if (!inputLength) {
            return inputOffset;
        }
        let resultOffset = -1;
        if (this.isConstructed) {
            resultOffset = LocalConstructedValueBlock.prototype.fromBER.call(this, inputBuffer, inputOffset, inputLength);
            if (resultOffset === -1)
                return resultOffset;
            for (const value of this.value) {
                const currentBlockName = value.constructor.NAME;
                if (currentBlockName === END_OF_CONTENT_NAME) {
                    if (this.isIndefiniteForm)
                        break;
                    else {
                        this.error = "EndOfContent is unexpected, BIT STRING may consists of BIT STRINGs only";
                        return -1;
                    }
                }
                if (currentBlockName !== BIT_STRING_NAME) {
                    this.error = "BIT STRING may consists of BIT STRINGs only";
                    return -1;
                }
                const valueBlock = value.valueBlock;
                if ((this.unusedBits > 0) && (valueBlock.unusedBits > 0)) {
                    this.error = "Using of \"unused bits\" inside constructive BIT STRING allowed for least one only";
                    return -1;
                }
                this.unusedBits = valueBlock.unusedBits;
            }
            return resultOffset;
        }
        const inputView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        if (!checkBufferParams(this, inputView, inputOffset, inputLength)) {
            return -1;
        }
        const intBuffer = inputView.subarray(inputOffset, inputOffset + inputLength);
        this.unusedBits = intBuffer[0];
        if (this.unusedBits > 7) {
            this.error = "Unused bits for BitString must be in range 0-7";
            return -1;
        }
        if (!this.unusedBits) {
            const buf = intBuffer.subarray(1);
            try {
                if (buf.byteLength) {
                    const asn = localFromBER(buf, 0, buf.byteLength);
                    if (asn.offset !== -1 && asn.offset === (inputLength - 1)) {
                        this.value = [asn.result];
                    }
                }
            }
            catch {
            }
        }
        this.valueHexView = intBuffer.subarray(1);
        this.blockLength = intBuffer.length;
        return (inputOffset + inputLength);
    }
    toBER(sizeOnly, writer) {
        if (this.isConstructed) {
            return LocalConstructedValueBlock.prototype.toBER.call(this, sizeOnly, writer);
        }
        if (sizeOnly) {
            return new ArrayBuffer(this.valueHexView.byteLength + 1);
        }
        if (!this.valueHexView.byteLength) {
            return EMPTY_BUFFER;
        }
        const retView = new Uint8Array(this.valueHexView.length + 1);
        retView[0] = this.unusedBits;
        retView.set(this.valueHexView, 1);
        return retView.buffer;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            unusedBits: this.unusedBits,
            isConstructed: this.isConstructed,
        };
    }
}
LocalBitStringValueBlock.NAME = "BitStringValueBlock";

var _a$q;
class BitString extends BaseBlock {
    constructor({ idBlock = {}, lenBlock = {}, ...parameters } = {}) {
        var _b, _c;
        (_b = parameters.isConstructed) !== null && _b !== void 0 ? _b : (parameters.isConstructed = !!((_c = parameters.value) === null || _c === void 0 ? void 0 : _c.length));
        super({
            idBlock: {
                isConstructed: parameters.isConstructed,
                ...idBlock,
            },
            lenBlock: {
                ...lenBlock,
                isIndefiniteForm: !!parameters.isIndefiniteForm,
            },
            ...parameters,
        }, LocalBitStringValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 3;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        this.valueBlock.isConstructed = this.idBlock.isConstructed;
        this.valueBlock.isIndefiniteForm = this.lenBlock.isIndefiniteForm;
        return super.fromBER(inputBuffer, inputOffset, inputLength);
    }
    onAsciiEncoding() {
        if (this.valueBlock.isConstructed || (this.valueBlock.value && this.valueBlock.value.length)) {
            return Constructed.prototype.onAsciiEncoding.call(this);
        }
        else {
            const bits = [];
            const valueHex = this.valueBlock.valueHexView;
            for (const byte of valueHex) {
                bits.push(byte.toString(2).padStart(8, "0"));
            }
            const bitsStr = bits.join("");
            const name = this.constructor.NAME;
            const value = bitsStr.substring(0, bitsStr.length - this.valueBlock.unusedBits);
            return `${name} : ${value}`;
        }
    }
}
_a$q = BitString;
(() => {
    typeStore.BitString = _a$q;
})();
BitString.NAME = BIT_STRING_NAME;

var _a$p;
function viewAdd(first, second) {
    const c = new Uint8Array([0]);
    const firstView = new Uint8Array(first);
    const secondView = new Uint8Array(second);
    let firstViewCopy = firstView.slice(0);
    const firstViewCopyLength = firstViewCopy.length - 1;
    const secondViewCopy = secondView.slice(0);
    const secondViewCopyLength = secondViewCopy.length - 1;
    let value = 0;
    const max = (secondViewCopyLength < firstViewCopyLength) ? firstViewCopyLength : secondViewCopyLength;
    let counter = 0;
    for (let i = max; i >= 0; i--, counter++) {
        switch (true) {
            case (counter < secondViewCopy.length):
                value = firstViewCopy[firstViewCopyLength - counter] + secondViewCopy[secondViewCopyLength - counter] + c[0];
                break;
            default:
                value = firstViewCopy[firstViewCopyLength - counter] + c[0];
        }
        c[0] = value / 10;
        switch (true) {
            case (counter >= firstViewCopy.length):
                firstViewCopy = pvutils__namespace.utilConcatView(new Uint8Array([value % 10]), firstViewCopy);
                break;
            default:
                firstViewCopy[firstViewCopyLength - counter] = value % 10;
        }
    }
    if (c[0] > 0)
        firstViewCopy = pvutils__namespace.utilConcatView(c, firstViewCopy);
    return firstViewCopy;
}
function power2(n) {
    if (n >= powers2.length) {
        for (let p = powers2.length; p <= n; p++) {
            const c = new Uint8Array([0]);
            let digits = (powers2[p - 1]).slice(0);
            for (let i = (digits.length - 1); i >= 0; i--) {
                const newValue = new Uint8Array([(digits[i] << 1) + c[0]]);
                c[0] = newValue[0] / 10;
                digits[i] = newValue[0] % 10;
            }
            if (c[0] > 0)
                digits = pvutils__namespace.utilConcatView(c, digits);
            powers2.push(digits);
        }
    }
    return powers2[n];
}
function viewSub(first, second) {
    let b = 0;
    const firstView = new Uint8Array(first);
    const secondView = new Uint8Array(second);
    const firstViewCopy = firstView.slice(0);
    const firstViewCopyLength = firstViewCopy.length - 1;
    const secondViewCopy = secondView.slice(0);
    const secondViewCopyLength = secondViewCopy.length - 1;
    let value;
    let counter = 0;
    for (let i = secondViewCopyLength; i >= 0; i--, counter++) {
        value = firstViewCopy[firstViewCopyLength - counter] - secondViewCopy[secondViewCopyLength - counter] - b;
        switch (true) {
            case (value < 0):
                b = 1;
                firstViewCopy[firstViewCopyLength - counter] = value + 10;
                break;
            default:
                b = 0;
                firstViewCopy[firstViewCopyLength - counter] = value;
        }
    }
    if (b > 0) {
        for (let i = (firstViewCopyLength - secondViewCopyLength + 1); i >= 0; i--, counter++) {
            value = firstViewCopy[firstViewCopyLength - counter] - b;
            if (value < 0) {
                b = 1;
                firstViewCopy[firstViewCopyLength - counter] = value + 10;
            }
            else {
                b = 0;
                firstViewCopy[firstViewCopyLength - counter] = value;
                break;
            }
        }
    }
    return firstViewCopy.slice();
}
class LocalIntegerValueBlock extends HexBlock(ValueBlock) {
    setValueHex() {
        if (this.valueHexView.length >= 4) {
            this.warnings.push("Too big Integer for decoding, hex only");
            this.isHexOnly = true;
            this._valueDec = 0;
        }
        else {
            this.isHexOnly = false;
            if (this.valueHexView.length > 0) {
                this._valueDec = pvutils__namespace.utilDecodeTC.call(this);
            }
        }
    }
    constructor({ value, ...parameters } = {}) {
        super(parameters);
        this._valueDec = 0;
        if (parameters.valueHex) {
            this.setValueHex();
        }
        if (value !== undefined) {
            this.valueDec = value;
        }
    }
    set valueDec(v) {
        this._valueDec = v;
        this.isHexOnly = false;
        this.valueHexView = new Uint8Array(pvutils__namespace.utilEncodeTC(v));
    }
    get valueDec() {
        return this._valueDec;
    }
    fromDER(inputBuffer, inputOffset, inputLength, expectedLength = 0) {
        const offset = this.fromBER(inputBuffer, inputOffset, inputLength);
        if (offset === -1)
            return offset;
        const view = this.valueHexView;
        if ((view[0] === 0x00) && ((view[1] & 0x80) !== 0)) {
            this.valueHexView = view.subarray(1);
        }
        else {
            if (expectedLength !== 0) {
                if (view.length < expectedLength) {
                    if ((expectedLength - view.length) > 1)
                        expectedLength = view.length + 1;
                    this.valueHexView = view.subarray(expectedLength - view.length);
                }
            }
        }
        return offset;
    }
    toDER(sizeOnly = false) {
        const view = this.valueHexView;
        switch (true) {
            case ((view[0] & 0x80) !== 0):
                {
                    const updatedView = new Uint8Array(this.valueHexView.length + 1);
                    updatedView[0] = 0x00;
                    updatedView.set(view, 1);
                    this.valueHexView = updatedView;
                }
                break;
            case ((view[0] === 0x00) && ((view[1] & 0x80) === 0)):
                {
                    this.valueHexView = this.valueHexView.subarray(1);
                }
                break;
        }
        return this.toBER(sizeOnly);
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const resultOffset = super.fromBER(inputBuffer, inputOffset, inputLength);
        if (resultOffset === -1) {
            return resultOffset;
        }
        this.setValueHex();
        return resultOffset;
    }
    toBER(sizeOnly) {
        return sizeOnly
            ? new ArrayBuffer(this.valueHexView.length)
            : this.valueHexView.slice().buffer;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            valueDec: this.valueDec,
        };
    }
    toString() {
        const firstBit = (this.valueHexView.length * 8) - 1;
        let digits = new Uint8Array((this.valueHexView.length * 8) / 3);
        let bitNumber = 0;
        let currentByte;
        const asn1View = this.valueHexView;
        let result = "";
        let flag = false;
        for (let byteNumber = (asn1View.byteLength - 1); byteNumber >= 0; byteNumber--) {
            currentByte = asn1View[byteNumber];
            for (let i = 0; i < 8; i++) {
                if ((currentByte & 1) === 1) {
                    switch (bitNumber) {
                        case firstBit:
                            digits = viewSub(power2(bitNumber), digits);
                            result = "-";
                            break;
                        default:
                            digits = viewAdd(digits, power2(bitNumber));
                    }
                }
                bitNumber++;
                currentByte >>= 1;
            }
        }
        for (let i = 0; i < digits.length; i++) {
            if (digits[i])
                flag = true;
            if (flag)
                result += digitsString.charAt(digits[i]);
        }
        if (flag === false)
            result += digitsString.charAt(0);
        return result;
    }
}
_a$p = LocalIntegerValueBlock;
LocalIntegerValueBlock.NAME = "IntegerValueBlock";
(() => {
    Object.defineProperty(_a$p.prototype, "valueHex", {
        set: function (v) {
            this.valueHexView = new Uint8Array(v);
            this.setValueHex();
        },
        get: function () {
            return this.valueHexView.slice().buffer;
        },
    });
})();

var _a$o;
class Integer extends BaseBlock {
    constructor(parameters = {}) {
        super(parameters, LocalIntegerValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 2;
    }
    toBigInt() {
        assertBigInt();
        return BigInt(this.valueBlock.toString());
    }
    static fromBigInt(value) {
        assertBigInt();
        const bigIntValue = BigInt(value);
        const writer = new ViewWriter();
        const hex = bigIntValue.toString(16).replace(/^-/, "");
        const view = new Uint8Array(pvtsutils__namespace.Convert.FromHex(hex));
        if (bigIntValue < 0) {
            const first = new Uint8Array(view.length + (view[0] & 0x80 ? 1 : 0));
            first[0] |= 0x80;
            const firstInt = BigInt(`0x${pvtsutils__namespace.Convert.ToHex(first)}`);
            const secondInt = firstInt + bigIntValue;
            const second = pvtsutils__namespace.BufferSourceConverter.toUint8Array(pvtsutils__namespace.Convert.FromHex(secondInt.toString(16)));
            second[0] |= 0x80;
            writer.write(second);
        }
        else {
            if (view[0] & 0x80) {
                writer.write(new Uint8Array([0]));
            }
            writer.write(view);
        }
        const res = new _a$o({ valueHex: writer.final() });
        return res;
    }
    convertToDER() {
        const integer = new _a$o({ valueHex: this.valueBlock.valueHexView });
        integer.valueBlock.toDER();
        return integer;
    }
    convertFromDER() {
        return new _a$o({
            valueHex: this.valueBlock.valueHexView[0] === 0
                ? this.valueBlock.valueHexView.subarray(1)
                : this.valueBlock.valueHexView,
        });
    }
    onAsciiEncoding() {
        return `${this.constructor.NAME} : ${this.valueBlock.toString()}`;
    }
}
_a$o = Integer;
(() => {
    typeStore.Integer = _a$o;
})();
Integer.NAME = "INTEGER";

var _a$n;
class Enumerated extends Integer {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 10;
    }
}
_a$n = Enumerated;
(() => {
    typeStore.Enumerated = _a$n;
})();
Enumerated.NAME = "ENUMERATED";

class LocalSidValueBlock extends HexBlock(ValueBlock) {
    constructor({ valueDec = -1, isFirstSid = false, ...parameters } = {}) {
        super(parameters);
        this.valueDec = valueDec;
        this.isFirstSid = isFirstSid;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        if (!inputLength) {
            return inputOffset;
        }
        const inputView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        if (!checkBufferParams(this, inputView, inputOffset, inputLength)) {
            return -1;
        }
        const intBuffer = inputView.subarray(inputOffset, inputOffset + inputLength);
        this.valueHexView = new Uint8Array(inputLength);
        for (let i = 0; i < inputLength; i++) {
            this.valueHexView[i] = intBuffer[i] & 0x7F;
            this.blockLength++;
            if ((intBuffer[i] & 0x80) === 0x00)
                break;
        }
        const tempView = new Uint8Array(this.blockLength);
        for (let i = 0; i < this.blockLength; i++) {
            tempView[i] = this.valueHexView[i];
        }
        this.valueHexView = tempView;
        if ((intBuffer[this.blockLength - 1] & 0x80) !== 0x00) {
            this.error = "End of input reached before message was fully decoded";
            return -1;
        }
        if (this.valueHexView[0] === 0x00)
            this.warnings.push("Needlessly long format of SID encoding");
        if (this.blockLength <= 8)
            this.valueDec = pvutils__namespace.utilFromBase(this.valueHexView, 7);
        else {
            this.isHexOnly = true;
            this.warnings.push("Too big SID for decoding, hex only");
        }
        return (inputOffset + this.blockLength);
    }
    set valueBigInt(value) {
        assertBigInt();
        let bits = BigInt(value).toString(2);
        while (bits.length % 7) {
            bits = "0" + bits;
        }
        const bytes = new Uint8Array(bits.length / 7);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(bits.slice(i * 7, i * 7 + 7), 2) + (i + 1 < bytes.length ? 0x80 : 0);
        }
        this.fromBER(bytes.buffer, 0, bytes.length);
    }
    toBER(sizeOnly) {
        if (this.isHexOnly) {
            if (sizeOnly)
                return (new ArrayBuffer(this.valueHexView.byteLength));
            const curView = this.valueHexView;
            const retView = new Uint8Array(this.blockLength);
            for (let i = 0; i < (this.blockLength - 1); i++)
                retView[i] = curView[i] | 0x80;
            retView[this.blockLength - 1] = curView[this.blockLength - 1];
            return retView.buffer;
        }
        const encodedBuf = pvutils__namespace.utilToBase(this.valueDec, 7);
        if (encodedBuf.byteLength === 0) {
            this.error = "Error during encoding SID value";
            return EMPTY_BUFFER;
        }
        const retView = new Uint8Array(encodedBuf.byteLength);
        if (!sizeOnly) {
            const encodedView = new Uint8Array(encodedBuf);
            const len = encodedBuf.byteLength - 1;
            for (let i = 0; i < len; i++)
                retView[i] = encodedView[i] | 0x80;
            retView[len] = encodedView[len];
        }
        return retView;
    }
    toString() {
        let result = "";
        if (this.isHexOnly)
            result = pvtsutils__namespace.Convert.ToHex(this.valueHexView);
        else {
            if (this.isFirstSid) {
                let sidValue = this.valueDec;
                if (this.valueDec <= 39)
                    result = "0.";
                else {
                    if (this.valueDec <= 79) {
                        result = "1.";
                        sidValue -= 40;
                    }
                    else {
                        result = "2.";
                        sidValue -= 80;
                    }
                }
                result += sidValue.toString();
            }
            else
                result = this.valueDec.toString();
        }
        return result;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            valueDec: this.valueDec,
            isFirstSid: this.isFirstSid,
        };
    }
}
LocalSidValueBlock.NAME = "sidBlock";

class LocalObjectIdentifierValueBlock extends ValueBlock {
    constructor({ value = EMPTY_STRING, ...parameters } = {}) {
        super(parameters);
        this.value = [];
        if (value) {
            this.fromString(value);
        }
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        let resultOffset = inputOffset;
        while (inputLength > 0) {
            const sidBlock = new LocalSidValueBlock();
            resultOffset = sidBlock.fromBER(inputBuffer, resultOffset, inputLength);
            if (resultOffset === -1) {
                this.blockLength = 0;
                this.error = sidBlock.error;
                return resultOffset;
            }
            if (this.value.length === 0)
                sidBlock.isFirstSid = true;
            this.blockLength += sidBlock.blockLength;
            inputLength -= sidBlock.blockLength;
            this.value.push(sidBlock);
        }
        return resultOffset;
    }
    toBER(sizeOnly) {
        const retBuffers = [];
        for (let i = 0; i < this.value.length; i++) {
            const valueBuf = this.value[i].toBER(sizeOnly);
            if (valueBuf.byteLength === 0) {
                this.error = this.value[i].error;
                return EMPTY_BUFFER;
            }
            retBuffers.push(valueBuf);
        }
        return concat(retBuffers);
    }
    fromString(string) {
        this.value = [];
        let pos1 = 0;
        let pos2 = 0;
        let sid = "";
        let flag = false;
        do {
            pos2 = string.indexOf(".", pos1);
            if (pos2 === -1)
                sid = string.substring(pos1);
            else
                sid = string.substring(pos1, pos2);
            pos1 = pos2 + 1;
            if (flag) {
                const sidBlock = this.value[0];
                let plus = 0;
                switch (sidBlock.valueDec) {
                    case 0:
                        break;
                    case 1:
                        plus = 40;
                        break;
                    case 2:
                        plus = 80;
                        break;
                    default:
                        this.value = [];
                        return;
                }
                const parsedSID = parseInt(sid, 10);
                if (isNaN(parsedSID))
                    return;
                sidBlock.valueDec = parsedSID + plus;
                flag = false;
            }
            else {
                const sidBlock = new LocalSidValueBlock();
                if (sid > Number.MAX_SAFE_INTEGER) {
                    assertBigInt();
                    const sidValue = BigInt(sid);
                    sidBlock.valueBigInt = sidValue;
                }
                else {
                    sidBlock.valueDec = parseInt(sid, 10);
                    if (isNaN(sidBlock.valueDec))
                        return;
                }
                if (!this.value.length) {
                    sidBlock.isFirstSid = true;
                    flag = true;
                }
                this.value.push(sidBlock);
            }
        } while (pos2 !== -1);
    }
    toString() {
        let result = "";
        let isHexOnly = false;
        for (let i = 0; i < this.value.length; i++) {
            isHexOnly = this.value[i].isHexOnly;
            let sidStr = this.value[i].toString();
            if (i !== 0)
                result = `${result}.`;
            if (isHexOnly) {
                sidStr = `{${sidStr}}`;
                if (this.value[i].isFirstSid)
                    result = `2.{${sidStr} - 80}`;
                else
                    result += sidStr;
            }
            else
                result += sidStr;
        }
        return result;
    }
    toJSON() {
        const object = {
            ...super.toJSON(),
            value: this.toString(),
            sidArray: [],
        };
        for (let i = 0; i < this.value.length; i++) {
            object.sidArray.push(this.value[i].toJSON());
        }
        return object;
    }
}
LocalObjectIdentifierValueBlock.NAME = "ObjectIdentifierValueBlock";

var _a$m;
class ObjectIdentifier extends BaseBlock {
    getValue() {
        return this.valueBlock.toString();
    }
    setValue(value) {
        this.valueBlock.fromString(value);
    }
    constructor(parameters = {}) {
        super(parameters, LocalObjectIdentifierValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 6;
    }
    onAsciiEncoding() {
        return `${this.constructor.NAME} : ${this.valueBlock.toString() || "empty"}`;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            value: this.getValue(),
        };
    }
}
_a$m = ObjectIdentifier;
(() => {
    typeStore.ObjectIdentifier = _a$m;
})();
ObjectIdentifier.NAME = "OBJECT IDENTIFIER";

class LocalRelativeSidValueBlock extends HexBlock(LocalBaseBlock) {
    constructor({ valueDec = 0, ...parameters } = {}) {
        super(parameters);
        this.valueDec = valueDec;
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        if (inputLength === 0)
            return inputOffset;
        const inputView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        if (!checkBufferParams(this, inputView, inputOffset, inputLength))
            return -1;
        const intBuffer = inputView.subarray(inputOffset, inputOffset + inputLength);
        this.valueHexView = new Uint8Array(inputLength);
        for (let i = 0; i < inputLength; i++) {
            this.valueHexView[i] = intBuffer[i] & 0x7F;
            this.blockLength++;
            if ((intBuffer[i] & 0x80) === 0x00)
                break;
        }
        const tempView = new Uint8Array(this.blockLength);
        for (let i = 0; i < this.blockLength; i++)
            tempView[i] = this.valueHexView[i];
        this.valueHexView = tempView;
        if ((intBuffer[this.blockLength - 1] & 0x80) !== 0x00) {
            this.error = "End of input reached before message was fully decoded";
            return -1;
        }
        if (this.valueHexView[0] === 0x00)
            this.warnings.push("Needlessly long format of SID encoding");
        if (this.blockLength <= 8)
            this.valueDec = pvutils__namespace.utilFromBase(this.valueHexView, 7);
        else {
            this.isHexOnly = true;
            this.warnings.push("Too big SID for decoding, hex only");
        }
        return (inputOffset + this.blockLength);
    }
    toBER(sizeOnly) {
        if (this.isHexOnly) {
            if (sizeOnly)
                return (new ArrayBuffer(this.valueHexView.byteLength));
            const curView = this.valueHexView;
            const retView = new Uint8Array(this.blockLength);
            for (let i = 0; i < (this.blockLength - 1); i++)
                retView[i] = curView[i] | 0x80;
            retView[this.blockLength - 1] = curView[this.blockLength - 1];
            return retView.buffer;
        }
        const encodedBuf = pvutils__namespace.utilToBase(this.valueDec, 7);
        if (encodedBuf.byteLength === 0) {
            this.error = "Error during encoding SID value";
            return EMPTY_BUFFER;
        }
        const retView = new Uint8Array(encodedBuf.byteLength);
        if (!sizeOnly) {
            const encodedView = new Uint8Array(encodedBuf);
            const len = encodedBuf.byteLength - 1;
            for (let i = 0; i < len; i++)
                retView[i] = encodedView[i] | 0x80;
            retView[len] = encodedView[len];
        }
        return retView.buffer;
    }
    toString() {
        let result = "";
        if (this.isHexOnly)
            result = pvtsutils__namespace.Convert.ToHex(this.valueHexView);
        else {
            result = this.valueDec.toString();
        }
        return result;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            valueDec: this.valueDec,
        };
    }
}
LocalRelativeSidValueBlock.NAME = "relativeSidBlock";

class LocalRelativeObjectIdentifierValueBlock extends ValueBlock {
    constructor({ value = EMPTY_STRING, ...parameters } = {}) {
        super(parameters);
        this.value = [];
        if (value) {
            this.fromString(value);
        }
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        let resultOffset = inputOffset;
        while (inputLength > 0) {
            const sidBlock = new LocalRelativeSidValueBlock();
            resultOffset = sidBlock.fromBER(inputBuffer, resultOffset, inputLength);
            if (resultOffset === -1) {
                this.blockLength = 0;
                this.error = sidBlock.error;
                return resultOffset;
            }
            this.blockLength += sidBlock.blockLength;
            inputLength -= sidBlock.blockLength;
            this.value.push(sidBlock);
        }
        return resultOffset;
    }
    toBER(sizeOnly, _writer) {
        const retBuffers = [];
        for (let i = 0; i < this.value.length; i++) {
            const valueBuf = this.value[i].toBER(sizeOnly);
            if (valueBuf.byteLength === 0) {
                this.error = this.value[i].error;
                return EMPTY_BUFFER;
            }
            retBuffers.push(valueBuf);
        }
        return concat(retBuffers);
    }
    fromString(string) {
        this.value = [];
        let pos1 = 0;
        let pos2 = 0;
        let sid = "";
        do {
            pos2 = string.indexOf(".", pos1);
            if (pos2 === -1)
                sid = string.substring(pos1);
            else
                sid = string.substring(pos1, pos2);
            pos1 = pos2 + 1;
            const sidBlock = new LocalRelativeSidValueBlock();
            sidBlock.valueDec = parseInt(sid, 10);
            if (isNaN(sidBlock.valueDec))
                return true;
            this.value.push(sidBlock);
        } while (pos2 !== -1);
        return true;
    }
    toString() {
        let result = "";
        let isHexOnly = false;
        for (let i = 0; i < this.value.length; i++) {
            isHexOnly = this.value[i].isHexOnly;
            let sidStr = this.value[i].toString();
            if (i !== 0)
                result = `${result}.`;
            if (isHexOnly) {
                sidStr = `{${sidStr}}`;
                result += sidStr;
            }
            else
                result += sidStr;
        }
        return result;
    }
    toJSON() {
        const object = {
            ...super.toJSON(),
            value: this.toString(),
            sidArray: [],
        };
        for (let i = 0; i < this.value.length; i++)
            object.sidArray.push(this.value[i].toJSON());
        return object;
    }
}
LocalRelativeObjectIdentifierValueBlock.NAME = "RelativeObjectIdentifierValueBlock";

var _a$l;
class RelativeObjectIdentifier extends BaseBlock {
    getValue() {
        return this.valueBlock.toString();
    }
    setValue(value) {
        this.valueBlock.fromString(value);
    }
    constructor(parameters = {}) {
        super(parameters, LocalRelativeObjectIdentifierValueBlock);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 13;
    }
    onAsciiEncoding() {
        return `${this.constructor.NAME} : ${this.valueBlock.toString() || "empty"}`;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            value: this.getValue(),
        };
    }
}
_a$l = RelativeObjectIdentifier;
(() => {
    typeStore.RelativeObjectIdentifier = _a$l;
})();
RelativeObjectIdentifier.NAME = "RelativeObjectIdentifier";

var _a$k;
class Sequence extends Constructed {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 16;
    }
}
_a$k = Sequence;
(() => {
    typeStore.Sequence = _a$k;
})();
Sequence.NAME = "SEQUENCE";

var _a$j;
class Set extends Constructed {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 17;
    }
}
_a$j = Set;
(() => {
    typeStore.Set = _a$j;
})();
Set.NAME = "SET";

class LocalStringValueBlock extends HexBlock(ValueBlock) {
    constructor({ ...parameters } = {}) {
        super(parameters);
        this.isHexOnly = true;
        this.value = EMPTY_STRING;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            value: this.value,
        };
    }
}
LocalStringValueBlock.NAME = "StringValueBlock";

class LocalSimpleStringValueBlock extends LocalStringValueBlock {
}
LocalSimpleStringValueBlock.NAME = "SimpleStringValueBlock";

class LocalSimpleStringBlock extends BaseStringBlock {
    constructor({ ...parameters } = {}) {
        super(parameters, LocalSimpleStringValueBlock);
    }
    fromBuffer(inputBuffer) {
        this.valueBlock.value = String.fromCharCode.apply(null, pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer));
    }
    fromString(inputString) {
        const strLen = inputString.length;
        const view = this.valueBlock.valueHexView = new Uint8Array(strLen);
        for (let i = 0; i < strLen; i++)
            view[i] = inputString.charCodeAt(i);
        this.valueBlock.value = inputString;
    }
}
LocalSimpleStringBlock.NAME = "SIMPLE STRING";

class LocalUtf8StringValueBlock extends LocalSimpleStringBlock {
    fromBuffer(inputBuffer) {
        this.valueBlock.valueHexView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
        try {
            this.valueBlock.value = pvtsutils__namespace.Convert.ToUtf8String(inputBuffer);
        }
        catch (ex) {
            this.warnings.push(`Error during "decodeURIComponent": ${ex}, using raw string`);
            this.valueBlock.value = pvtsutils__namespace.Convert.ToBinary(inputBuffer);
        }
    }
    fromString(inputString) {
        this.valueBlock.valueHexView = new Uint8Array(pvtsutils__namespace.Convert.FromUtf8String(inputString));
        this.valueBlock.value = inputString;
    }
}
LocalUtf8StringValueBlock.NAME = "Utf8StringValueBlock";

var _a$i;
class Utf8String extends LocalUtf8StringValueBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 12;
    }
}
_a$i = Utf8String;
(() => {
    typeStore.Utf8String = _a$i;
})();
Utf8String.NAME = "UTF8String";

class LocalBmpStringValueBlock extends LocalSimpleStringBlock {
    fromBuffer(inputBuffer) {
        this.valueBlock.value = pvtsutils__namespace.Convert.ToUtf16String(inputBuffer);
        this.valueBlock.valueHexView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer);
    }
    fromString(inputString) {
        this.valueBlock.value = inputString;
        this.valueBlock.valueHexView = new Uint8Array(pvtsutils__namespace.Convert.FromUtf16String(inputString));
    }
}
LocalBmpStringValueBlock.NAME = "BmpStringValueBlock";

var _a$h;
class BmpString extends LocalBmpStringValueBlock {
    constructor({ ...parameters } = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 30;
    }
}
_a$h = BmpString;
(() => {
    typeStore.BmpString = _a$h;
})();
BmpString.NAME = "BMPString";

class LocalUniversalStringValueBlock extends LocalSimpleStringBlock {
    fromBuffer(inputBuffer) {
        const copyBuffer = ArrayBuffer.isView(inputBuffer) ? inputBuffer.slice().buffer : inputBuffer.slice(0);
        const valueView = new Uint8Array(copyBuffer);
        for (let i = 0; i < valueView.length; i += 4) {
            valueView[i] = valueView[i + 3];
            valueView[i + 1] = valueView[i + 2];
            valueView[i + 2] = 0x00;
            valueView[i + 3] = 0x00;
        }
        this.valueBlock.value = String.fromCharCode.apply(null, new Uint32Array(copyBuffer));
    }
    fromString(inputString) {
        const strLength = inputString.length;
        const valueHexView = this.valueBlock.valueHexView = new Uint8Array(strLength * 4);
        for (let i = 0; i < strLength; i++) {
            const codeBuf = pvutils__namespace.utilToBase(inputString.charCodeAt(i), 8);
            const codeView = new Uint8Array(codeBuf);
            if (codeView.length > 4)
                continue;
            const dif = 4 - codeView.length;
            for (let j = (codeView.length - 1); j >= 0; j--)
                valueHexView[i * 4 + j + dif] = codeView[j];
        }
        this.valueBlock.value = inputString;
    }
}
LocalUniversalStringValueBlock.NAME = "UniversalStringValueBlock";

var _a$g;
class UniversalString extends LocalUniversalStringValueBlock {
    constructor({ ...parameters } = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 28;
    }
}
_a$g = UniversalString;
(() => {
    typeStore.UniversalString = _a$g;
})();
UniversalString.NAME = "UniversalString";

var _a$f;
class NumericString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 18;
    }
}
_a$f = NumericString;
(() => {
    typeStore.NumericString = _a$f;
})();
NumericString.NAME = "NumericString";

var _a$e;
class PrintableString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 19;
    }
}
_a$e = PrintableString;
(() => {
    typeStore.PrintableString = _a$e;
})();
PrintableString.NAME = "PrintableString";

var _a$d;
class TeletexString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 20;
    }
}
_a$d = TeletexString;
(() => {
    typeStore.TeletexString = _a$d;
})();
TeletexString.NAME = "TeletexString";

var _a$c;
class VideotexString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 21;
    }
}
_a$c = VideotexString;
(() => {
    typeStore.VideotexString = _a$c;
})();
VideotexString.NAME = "VideotexString";

var _a$b;
class IA5String extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 22;
    }
}
_a$b = IA5String;
(() => {
    typeStore.IA5String = _a$b;
})();
IA5String.NAME = "IA5String";

var _a$a;
class GraphicString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 25;
    }
}
_a$a = GraphicString;
(() => {
    typeStore.GraphicString = _a$a;
})();
GraphicString.NAME = "GraphicString";

var _a$9;
class VisibleString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 26;
    }
}
_a$9 = VisibleString;
(() => {
    typeStore.VisibleString = _a$9;
})();
VisibleString.NAME = "VisibleString";

var _a$8;
class GeneralString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 27;
    }
}
_a$8 = GeneralString;
(() => {
    typeStore.GeneralString = _a$8;
})();
GeneralString.NAME = "GeneralString";

var _a$7;
class CharacterString extends LocalSimpleStringBlock {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 29;
    }
}
_a$7 = CharacterString;
(() => {
    typeStore.CharacterString = _a$7;
})();
CharacterString.NAME = "CharacterString";

var _a$6;
class UTCTime extends VisibleString {
    constructor({ value, valueDate, ...parameters } = {}) {
        super(parameters);
        this.year = 0;
        this.month = 0;
        this.day = 0;
        this.hour = 0;
        this.minute = 0;
        this.second = 0;
        if (value) {
            this.fromString(value);
            this.valueBlock.valueHexView = new Uint8Array(value.length);
            for (let i = 0; i < value.length; i++)
                this.valueBlock.valueHexView[i] = value.charCodeAt(i);
        }
        if (valueDate) {
            this.fromDate(valueDate);
            this.valueBlock.valueHexView = new Uint8Array(this.toBuffer());
        }
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 23;
    }
    fromBuffer(inputBuffer) {
        this.fromString(String.fromCharCode.apply(null, pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer)));
    }
    toBuffer() {
        const str = this.toString();
        const buffer = new ArrayBuffer(str.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < str.length; i++)
            view[i] = str.charCodeAt(i);
        return buffer;
    }
    fromDate(inputDate) {
        this.year = inputDate.getUTCFullYear();
        this.month = inputDate.getUTCMonth() + 1;
        this.day = inputDate.getUTCDate();
        this.hour = inputDate.getUTCHours();
        this.minute = inputDate.getUTCMinutes();
        this.second = inputDate.getUTCSeconds();
    }
    toDate() {
        return (new Date(Date.UTC(this.year, this.month - 1, this.day, this.hour, this.minute, this.second)));
    }
    fromString(inputString) {
        const parser = /(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/ig;
        const parserArray = parser.exec(inputString);
        if (parserArray === null) {
            this.error = "Wrong input string for conversion";
            return;
        }
        const year = parseInt(parserArray[1], 10);
        if (year >= 50)
            this.year = 1900 + year;
        else
            this.year = 2000 + year;
        this.month = parseInt(parserArray[2], 10);
        this.day = parseInt(parserArray[3], 10);
        this.hour = parseInt(parserArray[4], 10);
        this.minute = parseInt(parserArray[5], 10);
        this.second = parseInt(parserArray[6], 10);
    }
    toString(encoding = "iso") {
        if (encoding === "iso") {
            const outputArray = new Array(7);
            outputArray[0] = pvutils__namespace.padNumber(((this.year < 2000) ? (this.year - 1900) : (this.year - 2000)), 2);
            outputArray[1] = pvutils__namespace.padNumber(this.month, 2);
            outputArray[2] = pvutils__namespace.padNumber(this.day, 2);
            outputArray[3] = pvutils__namespace.padNumber(this.hour, 2);
            outputArray[4] = pvutils__namespace.padNumber(this.minute, 2);
            outputArray[5] = pvutils__namespace.padNumber(this.second, 2);
            outputArray[6] = "Z";
            return outputArray.join("");
        }
        return super.toString(encoding);
    }
    onAsciiEncoding() {
        return `${this.constructor.NAME} : ${this.toDate().toISOString()}`;
    }
    toJSON() {
        return {
            ...super.toJSON(),
            year: this.year,
            month: this.month,
            day: this.day,
            hour: this.hour,
            minute: this.minute,
            second: this.second,
        };
    }
}
_a$6 = UTCTime;
(() => {
    typeStore.UTCTime = _a$6;
})();
UTCTime.NAME = "UTCTime";

var _a$5;
class GeneralizedTime extends UTCTime {
    constructor(parameters = {}) {
        var _b;
        super(parameters);
        (_b = this.millisecond) !== null && _b !== void 0 ? _b : (this.millisecond = 0);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 24;
    }
    fromDate(inputDate) {
        super.fromDate(inputDate);
        this.millisecond = inputDate.getUTCMilliseconds();
    }
    toDate() {
        const utcDate = Date.UTC(this.year, this.month - 1, this.day, this.hour, this.minute, this.second, this.millisecond);
        return (new Date(utcDate));
    }
    fromString(inputString) {
        let isUTC = false;
        let timeString = "";
        let dateTimeString = "";
        let fractionPart = 0;
        let parser;
        let hourDifference = 0;
        let minuteDifference = 0;
        if (inputString[inputString.length - 1] === "Z") {
            timeString = inputString.substring(0, inputString.length - 1);
            isUTC = true;
        }
        else {
            const number = new Number(inputString[inputString.length - 1]);
            if (isNaN(number.valueOf()))
                throw new Error("Wrong input string for conversion");
            timeString = inputString;
        }
        if (isUTC) {
            if (timeString.indexOf("+") !== -1)
                throw new Error("Wrong input string for conversion");
            if (timeString.indexOf("-") !== -1)
                throw new Error("Wrong input string for conversion");
        }
        else {
            let multiplier = 1;
            let differencePosition = timeString.indexOf("+");
            let differenceString = "";
            if (differencePosition === -1) {
                differencePosition = timeString.indexOf("-");
                multiplier = -1;
            }
            if (differencePosition !== -1) {
                differenceString = timeString.substring(differencePosition + 1);
                timeString = timeString.substring(0, differencePosition);
                if ((differenceString.length !== 2) && (differenceString.length !== 4))
                    throw new Error("Wrong input string for conversion");
                let number = parseInt(differenceString.substring(0, 2), 10);
                if (isNaN(number.valueOf()))
                    throw new Error("Wrong input string for conversion");
                hourDifference = multiplier * number;
                if (differenceString.length === 4) {
                    number = parseInt(differenceString.substring(2, 4), 10);
                    if (isNaN(number.valueOf()))
                        throw new Error("Wrong input string for conversion");
                    minuteDifference = multiplier * number;
                }
            }
        }
        let fractionPointPosition = timeString.indexOf(".");
        if (fractionPointPosition === -1)
            fractionPointPosition = timeString.indexOf(",");
        if (fractionPointPosition !== -1) {
            const fractionPartCheck = new Number(`0${timeString.substring(fractionPointPosition)}`);
            if (isNaN(fractionPartCheck.valueOf()))
                throw new Error("Wrong input string for conversion");
            fractionPart = fractionPartCheck.valueOf();
            dateTimeString = timeString.substring(0, fractionPointPosition);
        }
        else
            dateTimeString = timeString;
        switch (true) {
            case (dateTimeString.length === 8):
                parser = /(\d{4})(\d{2})(\d{2})/ig;
                if (fractionPointPosition !== -1)
                    throw new Error("Wrong input string for conversion");
                break;
            case (dateTimeString.length === 10):
                parser = /(\d{4})(\d{2})(\d{2})(\d{2})/ig;
                if (fractionPointPosition !== -1) {
                    let fractionResult = 60 * fractionPart;
                    this.minute = Math.floor(fractionResult);
                    fractionResult = 60 * (fractionResult - this.minute);
                    this.second = Math.floor(fractionResult);
                    fractionResult = 1000 * (fractionResult - this.second);
                    this.millisecond = Math.floor(fractionResult);
                }
                break;
            case (dateTimeString.length === 12):
                parser = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})/ig;
                if (fractionPointPosition !== -1) {
                    let fractionResult = 60 * fractionPart;
                    this.second = Math.floor(fractionResult);
                    fractionResult = 1000 * (fractionResult - this.second);
                    this.millisecond = Math.floor(fractionResult);
                }
                break;
            case (dateTimeString.length === 14):
                parser = /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/ig;
                if (fractionPointPosition !== -1) {
                    const fractionResult = 1000 * fractionPart;
                    this.millisecond = Math.floor(fractionResult);
                }
                break;
            default:
                throw new Error("Wrong input string for conversion");
        }
        const parserArray = parser.exec(dateTimeString);
        if (parserArray === null)
            throw new Error("Wrong input string for conversion");
        for (let j = 1; j < parserArray.length; j++) {
            switch (j) {
                case 1:
                    this.year = parseInt(parserArray[j], 10);
                    break;
                case 2:
                    this.month = parseInt(parserArray[j], 10);
                    break;
                case 3:
                    this.day = parseInt(parserArray[j], 10);
                    break;
                case 4:
                    this.hour = parseInt(parserArray[j], 10) + hourDifference;
                    break;
                case 5:
                    this.minute = parseInt(parserArray[j], 10) + minuteDifference;
                    break;
                case 6:
                    this.second = parseInt(parserArray[j], 10);
                    break;
                default:
                    throw new Error("Wrong input string for conversion");
            }
        }
        if (isUTC === false) {
            const tempDate = new Date(this.year, this.month, this.day, this.hour, this.minute, this.second, this.millisecond);
            this.year = tempDate.getUTCFullYear();
            this.month = tempDate.getUTCMonth();
            this.day = tempDate.getUTCDay();
            this.hour = tempDate.getUTCHours();
            this.minute = tempDate.getUTCMinutes();
            this.second = tempDate.getUTCSeconds();
            this.millisecond = tempDate.getUTCMilliseconds();
        }
    }
    toString(encoding = "iso") {
        if (encoding === "iso") {
            const outputArray = [];
            outputArray.push(pvutils__namespace.padNumber(this.year, 4));
            outputArray.push(pvutils__namespace.padNumber(this.month, 2));
            outputArray.push(pvutils__namespace.padNumber(this.day, 2));
            outputArray.push(pvutils__namespace.padNumber(this.hour, 2));
            outputArray.push(pvutils__namespace.padNumber(this.minute, 2));
            outputArray.push(pvutils__namespace.padNumber(this.second, 2));
            if (this.millisecond !== 0) {
                outputArray.push(".");
                outputArray.push(pvutils__namespace.padNumber(this.millisecond, 3));
            }
            outputArray.push("Z");
            return outputArray.join("");
        }
        return super.toString(encoding);
    }
    toJSON() {
        return {
            ...super.toJSON(),
            millisecond: this.millisecond,
        };
    }
}
_a$5 = GeneralizedTime;
(() => {
    typeStore.GeneralizedTime = _a$5;
})();
GeneralizedTime.NAME = "GeneralizedTime";

var _a$4;
class DATE extends Utf8String {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 31;
    }
}
_a$4 = DATE;
(() => {
    typeStore.DATE = _a$4;
})();
DATE.NAME = "DATE";

var _a$3;
class TimeOfDay extends Utf8String {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 32;
    }
}
_a$3 = TimeOfDay;
(() => {
    typeStore.TimeOfDay = _a$3;
})();
TimeOfDay.NAME = "TimeOfDay";

var _a$2;
class DateTime extends Utf8String {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 33;
    }
}
_a$2 = DateTime;
(() => {
    typeStore.DateTime = _a$2;
})();
DateTime.NAME = "DateTime";

var _a$1;
class Duration extends Utf8String {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 34;
    }
}
_a$1 = Duration;
(() => {
    typeStore.Duration = _a$1;
})();
Duration.NAME = "Duration";

var _a;
class TIME extends Utf8String {
    constructor(parameters = {}) {
        super(parameters);
        this.idBlock.tagClass = 1;
        this.idBlock.tagNumber = 14;
    }
}
_a = TIME;
(() => {
    typeStore.TIME = _a;
})();
TIME.NAME = "TIME";

class Any {
    constructor({ name = EMPTY_STRING, optional = false } = {}) {
        this.name = name;
        this.optional = optional;
    }
}

class Choice extends Any {
    constructor({ value = [], ...parameters } = {}) {
        super(parameters);
        this.value = value;
    }
}

class Repeated extends Any {
    constructor({ value = new Any(), local = false, ...parameters } = {}) {
        super(parameters);
        this.value = value;
        this.local = local;
    }
}

class RawData {
    get data() {
        return this.dataView.slice().buffer;
    }
    set data(value) {
        this.dataView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(value);
    }
    constructor({ data = EMPTY_VIEW } = {}) {
        this.dataView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(data);
    }
    fromBER(inputBuffer, inputOffset, inputLength) {
        const endLength = inputOffset + inputLength;
        this.dataView = pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer).subarray(inputOffset, endLength);
        return endLength;
    }
    toBER(_sizeOnly) {
        return this.dataView.slice().buffer;
    }
}

function compareSchema(root, inputData, inputSchema) {
    if (inputSchema instanceof Choice) {
        for (const element of inputSchema.value) {
            const result = compareSchema(root, inputData, element);
            if (result.verified) {
                return {
                    verified: true,
                    result: root,
                };
            }
        }
        {
            const _result = {
                verified: false,
                result: { error: "Wrong values for Choice type" },
            };
            if (inputSchema.hasOwnProperty(NAME))
                _result.name = inputSchema.name;
            return _result;
        }
    }
    if (inputSchema instanceof Any) {
        if (inputSchema.hasOwnProperty(NAME))
            root[inputSchema.name] = inputData;
        return {
            verified: true,
            result: root,
        };
    }
    if ((root instanceof Object) === false) {
        return {
            verified: false,
            result: { error: "Wrong root object" },
        };
    }
    if ((inputData instanceof Object) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 data" },
        };
    }
    if ((inputSchema instanceof Object) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    if ((ID_BLOCK in inputSchema) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    if ((FROM_BER in inputSchema.idBlock) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    if ((TO_BER in inputSchema.idBlock) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    const encodedId = inputSchema.idBlock.toBER(false);
    if (encodedId.byteLength === 0) {
        return {
            verified: false,
            result: { error: "Error encoding idBlock for ASN.1 schema" },
        };
    }
    const decodedOffset = inputSchema.idBlock.fromBER(encodedId, 0, encodedId.byteLength);
    if (decodedOffset === -1) {
        return {
            verified: false,
            result: { error: "Error decoding idBlock for ASN.1 schema" },
        };
    }
    if (inputSchema.idBlock.hasOwnProperty(TAG_CLASS) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    if (inputSchema.idBlock.tagClass !== inputData.idBlock.tagClass) {
        return {
            verified: false,
            result: root,
        };
    }
    if (inputSchema.idBlock.hasOwnProperty(TAG_NUMBER) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    if (inputSchema.idBlock.tagNumber !== inputData.idBlock.tagNumber) {
        return {
            verified: false,
            result: root,
        };
    }
    if (inputSchema.idBlock.hasOwnProperty(IS_CONSTRUCTED) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    if (inputSchema.idBlock.isConstructed !== inputData.idBlock.isConstructed) {
        return {
            verified: false,
            result: root,
        };
    }
    if (!(IS_HEX_ONLY in inputSchema.idBlock)) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema" },
        };
    }
    if (inputSchema.idBlock.isHexOnly !== inputData.idBlock.isHexOnly) {
        return {
            verified: false,
            result: root,
        };
    }
    if (inputSchema.idBlock.isHexOnly) {
        if ((VALUE_HEX_VIEW in inputSchema.idBlock) === false) {
            return {
                verified: false,
                result: { error: "Wrong ASN.1 schema" },
            };
        }
        const schemaView = inputSchema.idBlock.valueHexView;
        const asn1View = inputData.idBlock.valueHexView;
        if (schemaView.length !== asn1View.length) {
            return {
                verified: false,
                result: root,
            };
        }
        for (let i = 0; i < schemaView.length; i++) {
            if (schemaView[i] !== asn1View[1]) {
                return {
                    verified: false,
                    result: root,
                };
            }
        }
    }
    if (inputSchema.name) {
        inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, EMPTY_STRING);
        if (inputSchema.name)
            root[inputSchema.name] = inputData;
    }
    if (inputSchema instanceof typeStore.Constructed) {
        let admission = 0;
        let result = {
            verified: false,
            result: { error: "Unknown error" },
        };
        let maxLength = inputSchema.valueBlock.value.length;
        if (maxLength > 0) {
            if (inputSchema.valueBlock.value[0] instanceof Repeated) {
                maxLength = inputData.valueBlock.value.length;
            }
        }
        if (maxLength === 0) {
            return {
                verified: true,
                result: root,
            };
        }
        if ((inputData.valueBlock.value.length === 0)
            && (inputSchema.valueBlock.value.length !== 0)) {
            let _optional = true;
            for (let i = 0; i < inputSchema.valueBlock.value.length; i++)
                _optional = _optional && (inputSchema.valueBlock.value[i].optional || false);
            if (_optional) {
                return {
                    verified: true,
                    result: root,
                };
            }
            if (inputSchema.name) {
                inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, EMPTY_STRING);
                if (inputSchema.name)
                    delete root[inputSchema.name];
            }
            root.error = "Inconsistent object length";
            return {
                verified: false,
                result: root,
            };
        }
        for (let i = 0; i < maxLength; i++) {
            if ((i - admission) >= inputData.valueBlock.value.length) {
                if (inputSchema.valueBlock.value[i].optional === false) {
                    const _result = {
                        verified: false,
                        result: root,
                    };
                    root.error = "Inconsistent length between ASN.1 data and schema";
                    if (inputSchema.name) {
                        inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, EMPTY_STRING);
                        if (inputSchema.name) {
                            delete root[inputSchema.name];
                            _result.name = inputSchema.name;
                        }
                    }
                    return _result;
                }
            }
            else {
                if (inputSchema.valueBlock.value[0] instanceof Repeated) {
                    result = compareSchema(root, inputData.valueBlock.value[i], inputSchema.valueBlock.value[0].value);
                    if (result.verified === false) {
                        if (inputSchema.valueBlock.value[0].optional)
                            admission++;
                        else {
                            if (inputSchema.name) {
                                inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, EMPTY_STRING);
                                if (inputSchema.name)
                                    delete root[inputSchema.name];
                            }
                            return result;
                        }
                    }
                    if ((NAME in inputSchema.valueBlock.value[0]) && (inputSchema.valueBlock.value[0].name.length > 0)) {
                        let arrayRoot = {};
                        if ((LOCAL in inputSchema.valueBlock.value[0]) && (inputSchema.valueBlock.value[0].local))
                            arrayRoot = inputData;
                        else
                            arrayRoot = root;
                        if (typeof arrayRoot[inputSchema.valueBlock.value[0].name] === "undefined")
                            arrayRoot[inputSchema.valueBlock.value[0].name] = [];
                        arrayRoot[inputSchema.valueBlock.value[0].name].push(inputData.valueBlock.value[i]);
                    }
                }
                else {
                    result = compareSchema(root, inputData.valueBlock.value[i - admission], inputSchema.valueBlock.value[i]);
                    if (result.verified === false) {
                        if (inputSchema.valueBlock.value[i].optional)
                            admission++;
                        else {
                            if (inputSchema.name) {
                                inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, EMPTY_STRING);
                                if (inputSchema.name)
                                    delete root[inputSchema.name];
                            }
                            return result;
                        }
                    }
                }
            }
        }
        if (result.verified === false) {
            const _result = {
                verified: false,
                result: root,
            };
            if (inputSchema.name) {
                inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, EMPTY_STRING);
                if (inputSchema.name) {
                    delete root[inputSchema.name];
                    _result.name = inputSchema.name;
                }
            }
            return _result;
        }
        return {
            verified: true,
            result: root,
        };
    }
    if (inputSchema.primitiveSchema
        && (VALUE_HEX_VIEW in inputData.valueBlock)) {
        const asn1 = localFromBER(inputData.valueBlock.valueHexView);
        if (asn1.offset === -1) {
            const _result = {
                verified: false,
                result: asn1.result,
            };
            if (inputSchema.name) {
                inputSchema.name = inputSchema.name.replace(/^\s+|\s+$/g, EMPTY_STRING);
                if (inputSchema.name) {
                    delete root[inputSchema.name];
                    _result.name = inputSchema.name;
                }
            }
            return _result;
        }
        return compareSchema(root, asn1.result, inputSchema.primitiveSchema);
    }
    return {
        verified: true,
        result: root,
    };
}
function verifySchema(inputBuffer, inputSchema) {
    if ((inputSchema instanceof Object) === false) {
        return {
            verified: false,
            result: { error: "Wrong ASN.1 schema type" },
        };
    }
    const asn1 = localFromBER(pvtsutils__namespace.BufferSourceConverter.toUint8Array(inputBuffer));
    if (asn1.offset === -1) {
        return {
            verified: false,
            result: asn1.result,
        };
    }
    return compareSchema(asn1.result, asn1.result, inputSchema);
}

exports.Any = Any;
exports.BaseBlock = BaseBlock;
exports.BaseStringBlock = BaseStringBlock;
exports.BitString = BitString;
exports.BmpString = BmpString;
exports.Boolean = Boolean;
exports.CharacterString = CharacterString;
exports.Choice = Choice;
exports.Constructed = Constructed;
exports.DATE = DATE;
exports.DateTime = DateTime;
exports.Duration = Duration;
exports.EndOfContent = EndOfContent;
exports.Enumerated = Enumerated;
exports.GeneralString = GeneralString;
exports.GeneralizedTime = GeneralizedTime;
exports.GraphicString = GraphicString;
exports.HexBlock = HexBlock;
exports.IA5String = IA5String;
exports.Integer = Integer;
exports.Null = Null;
exports.NumericString = NumericString;
exports.ObjectIdentifier = ObjectIdentifier;
exports.OctetString = OctetString;
exports.Primitive = Primitive;
exports.PrintableString = PrintableString;
exports.RawData = RawData;
exports.RelativeObjectIdentifier = RelativeObjectIdentifier;
exports.Repeated = Repeated;
exports.Sequence = Sequence;
exports.Set = Set;
exports.TIME = TIME;
exports.TeletexString = TeletexString;
exports.TimeOfDay = TimeOfDay;
exports.UTCTime = UTCTime;
exports.UniversalString = UniversalString;
exports.Utf8String = Utf8String;
exports.ValueBlock = ValueBlock;
exports.VideotexString = VideotexString;
exports.ViewWriter = ViewWriter;
exports.VisibleString = VisibleString;
exports.compareSchema = compareSchema;
exports.fromBER = fromBER;
exports.verifySchema = verifySchema;

},{"pvtsutils":9,"pvutils":10}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bitsToStringArray = void 0;
exports.bitsToStringArray = [
    "00000000", "00000001", "00000010",
    "00000011", "00000100", "00000101",
    "00000110", "00000111", "00001000",
    "00001001", "00001010", "00001011",
    "00001100", "00001101", "00001110",
    "00001111", "00010000", "00010001",
    "00010010", "00010011", "00010100",
    "00010101", "00010110", "00010111",
    "00011000", "00011001", "00011010",
    "00011011", "00011100", "00011101",
    "00011110", "00011111", "00100000",
    "00100001", "00100010", "00100011",
    "00100100", "00100101", "00100110",
    "00100111", "00101000", "00101001",
    "00101010", "00101011", "00101100",
    "00101101", "00101110", "00101111",
    "00110000", "00110001", "00110010",
    "00110011", "00110100", "00110101",
    "00110110", "00110111", "00111000",
    "00111001", "00111010", "00111011",
    "00111100", "00111101", "00111110",
    "00111111", "01000000", "01000001",
    "01000010", "01000011", "01000100",
    "01000101", "01000110", "01000111",
    "01001000", "01001001", "01001010",
    "01001011", "01001100", "01001101",
    "01001110", "01001111", "01010000",
    "01010001", "01010010", "01010011",
    "01010100", "01010101", "01010110",
    "01010111", "01011000", "01011001",
    "01011010", "01011011", "01011100",
    "01011101", "01011110", "01011111",
    "01100000", "01100001", "01100010",
    "01100011", "01100100", "01100101",
    "01100110", "01100111", "01101000",
    "01101001", "01101010", "01101011",
    "01101100", "01101101", "01101110",
    "01101111", "01110000", "01110001",
    "01110010", "01110011", "01110100",
    "01110101", "01110110", "01110111",
    "01111000", "01111001", "01111010",
    "01111011", "01111100", "01111101",
    "01111110", "01111111", "10000000",
    "10000001", "10000010", "10000011",
    "10000100", "10000101", "10000110",
    "10000111", "10001000", "10001001",
    "10001010", "10001011", "10001100",
    "10001101", "10001110", "10001111",
    "10010000", "10010001", "10010010",
    "10010011", "10010100", "10010101",
    "10010110", "10010111", "10011000",
    "10011001", "10011010", "10011011",
    "10011100", "10011101", "10011110",
    "10011111", "10100000", "10100001",
    "10100010", "10100011", "10100100",
    "10100101", "10100110", "10100111",
    "10101000", "10101001", "10101010",
    "10101011", "10101100", "10101101",
    "10101110", "10101111", "10110000",
    "10110001", "10110010", "10110011",
    "10110100", "10110101", "10110110",
    "10110111", "10111000", "10111001",
    "10111010", "10111011", "10111100",
    "10111101", "10111110", "10111111",
    "11000000", "11000001", "11000010",
    "11000011", "11000100", "11000101",
    "11000110", "11000111", "11001000",
    "11001001", "11001010", "11001011",
    "11001100", "11001101", "11001110",
    "11001111", "11010000", "11010001",
    "11010010", "11010011", "11010100",
    "11010101", "11010110", "11010111",
    "11011000", "11011001", "11011010",
    "11011011", "11011100", "11011101",
    "11011110", "11011111", "11100000",
    "11100001", "11100010", "11100011",
    "11100100", "11100101", "11100110",
    "11100111", "11101000", "11101001",
    "11101010", "11101011", "11101100",
    "11101101", "11101110", "11101111",
    "11110000", "11110001", "11110010",
    "11110011", "11110100", "11110101",
    "11110110", "11110111", "11111000",
    "11111001", "11111010", "11111011",
    "11111100", "11111101", "11111110",
    "11111111"
];

},{}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BitStream = void 0;
const bit_1 = require("./bit");
const byte_stream_1 = require("./byte_stream");
class BitStream {
    constructor(parameters) {
        this.buffer = new ArrayBuffer(0);
        this.view = new Uint8Array(this.buffer);
        this.bitsCount = 0;
        if (parameters) {
            if ("byteStream" in parameters) {
                this.fromByteStream(parameters.byteStream);
            }
            if ("view" in parameters) {
                this.fromUint8Array(parameters.view);
            }
            if ("buffer" in parameters) {
                this.fromArrayBuffer(parameters.buffer);
            }
            if ("string" in parameters) {
                this.fromString(parameters.string);
            }
            if ("uint32" in parameters) {
                this.fromUint32(parameters.uint32);
            }
            if ("bitsCount" in parameters && parameters.bitsCount) {
                this.bitsCount = parameters.bitsCount;
            }
        }
    }
    clear() {
        this.buffer = new ArrayBuffer(0);
        this.view = new Uint8Array(this.buffer);
        this.bitsCount = 0;
    }
    fromByteStream(stream) {
        this.fromUint8Array(stream.view);
    }
    fromArrayBuffer(array) {
        this.buffer = array;
        this.view = new Uint8Array(array);
        this.bitsCount = this.view.length << 3;
    }
    fromUint8Array(array) {
        this.fromArrayBuffer(new Uint8Array(array).buffer);
    }
    fromString(string) {
        const stringLength = string.length;
        this.buffer = new ArrayBuffer((stringLength >> 3) + ((stringLength % 8) ? 1 : 0));
        this.view = new Uint8Array(this.buffer);
        this.bitsCount = ((stringLength >> 3) + 1) << 3;
        let byteIndex = 0;
        for (let i = 0; i < stringLength; i++) {
            if (string[i] == "1")
                this.view[byteIndex] |= 1 << (7 - (i % 8));
            if (i && (((i + 1) % 8) == 0))
                byteIndex++;
        }
        if (stringLength % 8)
            this.shiftRight(8 - (stringLength % 8));
        this.bitsCount = stringLength;
    }
    fromUint32(uint32) {
        this.buffer = new ArrayBuffer(4);
        this.view = new Uint8Array(this.buffer);
        const value = new Uint32Array([uint32]);
        const view = new Uint8Array(value.buffer);
        for (let i = 3; i >= 0; i--)
            this.view[i] = view[3 - i];
        this.bitsCount = 32;
    }
    toString(start, length) {
        if (start == null) {
            start = 0;
        }
        if ((start >= this.view.length) || (start < 0)) {
            start = 0;
        }
        if (length == null) {
            length = this.view.length - start;
        }
        if ((length >= this.view.length) || (length < 0)) {
            length = this.view.length - start;
        }
        const result = [];
        for (let i = start; i < (start + length); i++) {
            result.push(bit_1.bitsToStringArray[this.view[i]]);
        }
        return result.join("").substring((this.view.length << 3) - this.bitsCount);
    }
    shiftRight(shift, needShrink = true) {
        if (this.view.length == 0) {
            return;
        }
        if ((shift < 0) || (shift > 8)) {
            throw new Error("The \"shift\" parameter must be in range 0-8");
        }
        if (shift > this.bitsCount) {
            throw new Error("The \"shift\" parameter can not be bigger than \"this.bitsCount\"");
        }
        const shiftMask = 0xFF >> (8 - shift);
        this.view[this.view.length - 1] >>= shift;
        for (let i = (this.view.length - 2); i >= 0; i--) {
            this.view[i + 1] |= (this.view[i] & shiftMask) << (8 - shift);
            this.view[i] >>= shift;
        }
        this.bitsCount -= shift;
        if (this.bitsCount == 0) {
            this.clear();
        }
        if (needShrink) {
            this.shrink();
        }
    }
    shiftLeft(shift) {
        if (this.view.length == 0) {
            return;
        }
        if ((shift < 0) || (shift > 8)) {
            throw new Error("The \"shift\" parameter must be in range 0-8");
        }
        if (shift > this.bitsCount) {
            throw new Error("The \"shift\" parameter can not be bigger than \"this.bitsCount\"");
        }
        const bitsOffset = this.bitsCount & 0x07;
        if (bitsOffset > shift) {
            this.view[0] &= 0xFF >> (bitsOffset + shift);
        }
        else {
            const view = this.view.slice(1);
            view[0] &= 0xFF >> (shift - bitsOffset);
            this.buffer = view.buffer;
            this.view = view;
        }
        this.bitsCount -= shift;
        if (this.bitsCount == 0) {
            this.clear();
        }
    }
    slice(start = 0, end = 0) {
        let valueShift = 0;
        if (this.bitsCount % 8) {
            valueShift = (8 - (this.bitsCount % 8));
        }
        start += valueShift;
        end += valueShift;
        const maxEnd = (this.view.length << 3) - 1;
        if ((start < 0) || (start > maxEnd)) {
            return new BitStream();
        }
        if (!end) {
            end = maxEnd;
        }
        if ((end < 0) || (end > maxEnd)) {
            return new BitStream();
        }
        if ((end - start + 1) > this.bitsCount) {
            return new BitStream();
        }
        const startIndex = start >> 3;
        const startOffset = start & 0x07;
        const endIndex = end >> 3;
        const endOffset = end & 0x07;
        const bitsLength = ((endIndex - startIndex) == 0) ? 1 : (endIndex - startIndex + 1);
        const result = new BitStream({
            buffer: this.buffer.slice(startIndex, startIndex + bitsLength),
            bitsCount: bitsLength << 3,
        });
        result.view[0] &= (0xFF >> startOffset);
        result.view[bitsLength] &= (0xFF << (7 - endOffset));
        if (7 - endOffset) {
            result.shiftRight(7 - endOffset, false);
        }
        result.bitsCount = (end - start + 1);
        result.shrink();
        return result;
    }
    copy(start = 0, length = 0) {
        const maxEnd = (this.view.length << 3) - 1;
        if ((start < 0) || (start > maxEnd)) {
            return new BitStream();
        }
        if (!length) {
            length = (this.view.length << 3) - start - 1;
        }
        if (length > this.bitsCount) {
            return new BitStream();
        }
        return this.slice(start, start + length - 1);
    }
    shrink() {
        const currentLength = (this.bitsCount >> 3) + ((this.bitsCount % 8) ? 1 : 0);
        if (currentLength < this.view.length) {
            const view = this.view.slice(this.view.length - currentLength, (this.view.length - currentLength) + currentLength);
            this.view = view;
            this.buffer = view.buffer;
        }
    }
    reverseBytes() {
        for (let i = 0; i < this.view.length; i++) {
            this.view[i] = ((this.view[i] * 0x0802 & 0x22110) | (this.view[i] * 0x8020 & 0x88440)) * 0x10101 >> 16;
        }
        if (this.bitsCount % 8) {
            const currentLength = (this.bitsCount >> 3) + ((this.bitsCount % 8) ? 1 : 0);
            this.view[this.view.length - currentLength] >>= (8 - (this.bitsCount & 0x07));
        }
    }
    reverseValue() {
        const initialValue = this.toString();
        const initialValueLength = initialValue.length;
        const reversedValue = new Array(initialValueLength);
        for (let i = 0; i < initialValueLength; i++) {
            reversedValue[initialValueLength - 1 - i] = initialValue[i];
        }
        this.fromString(reversedValue.join(""));
    }
    getNumberValue() {
        const byteLength = (this.view.length - 1);
        if (byteLength > 3) {
            return (-1);
        }
        if (byteLength == (-1)) {
            return 0;
        }
        const value = new Uint32Array(1);
        const view = new Uint8Array(value.buffer);
        for (let i = byteLength; i >= 0; i--) {
            view[byteLength - i] = this.view[i];
        }
        return value[0];
    }
    findPattern(pattern, start, length, backward) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString(),
        });
        const stringPattern = new byte_stream_1.ByteStream({
            string: pattern.toString()
        });
        return stringStream.findPattern(stringPattern, start, length, backward);
    }
    findFirstIn(patterns, start, length, backward) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString(),
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findFirstIn(stringPatterns, start, length, backward);
    }
    findAllIn(patterns, start, length) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findAllIn(stringPatterns, start, length);
    }
    findAllPatternIn(pattern, start, length) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPattern = new byte_stream_1.ByteStream({
            string: pattern.toString()
        });
        return stringStream.findAllPatternIn(stringPattern, start, length);
    }
    findFirstNotIn(patterns, start, length, backward) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findFirstNotIn(stringPatterns, start, length, backward);
    }
    findAllNotIn(patterns, start, length) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findAllNotIn(stringPatterns, start, length);
    }
    findFirstSequence(patterns, start, length, backward) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findFirstSequence(stringPatterns, start, length, backward);
    }
    findAllSequences(patterns, start, length) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findAllSequences(stringPatterns, start, length);
    }
    findPairedPatterns(leftPattern, rightPattern, start, length) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringLeftPattern = new byte_stream_1.ByteStream({
            string: leftPattern.toString()
        });
        const stringRightPattern = new byte_stream_1.ByteStream({
            string: rightPattern.toString()
        });
        return stringStream.findPairedPatterns(stringLeftPattern, stringRightPattern, start, length);
    }
    findPairedArrays(inputLeftPatterns, inputRightPatterns, start, length) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringLeftPatterns = new Array(inputLeftPatterns.length);
        for (let i = 0; i < inputLeftPatterns.length; i++) {
            stringLeftPatterns[i] = new byte_stream_1.ByteStream({
                string: inputLeftPatterns[i].toString()
            });
        }
        const stringRightPatterns = new Array(inputRightPatterns.length);
        for (let i = 0; i < inputRightPatterns.length; i++) {
            stringRightPatterns[i] = new byte_stream_1.ByteStream({
                string: inputRightPatterns[i].toString()
            });
        }
        return stringStream.findPairedArrays(stringLeftPatterns, stringRightPatterns, start, length);
    }
    replacePattern(searchPattern, replacePattern, start, length) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringSearchPattern = new byte_stream_1.ByteStream({
            string: searchPattern.toString()
        });
        const stringReplacePattern = new byte_stream_1.ByteStream({
            string: replacePattern.toString()
        });
        if (stringStream.replacePattern(stringSearchPattern, stringReplacePattern, start, length)) {
            this.fromString(stringStream.toString());
            return true;
        }
        return false;
    }
    skipPatterns(patterns, start, length, backward) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.skipPatterns(stringPatterns, start, length, backward);
    }
    skipNotPatterns(patterns, start, length, backward) {
        const stringStream = new byte_stream_1.ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new byte_stream_1.ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.skipNotPatterns(stringPatterns, start, length, backward);
    }
    append(stream) {
        this.fromString([
            this.toString(),
            stream.toString()
        ].join(""));
    }
}
exports.BitStream = BitStream;

},{"./bit":2,"./byte_stream":4}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ByteStream = void 0;
class ByteStream {
    constructor(parameters = {}) {
        if ("view" in parameters) {
            this.fromUint8Array(parameters.view);
        }
        else if ("buffer" in parameters) {
            this.fromArrayBuffer(parameters.buffer);
        }
        else if ("string" in parameters) {
            this.fromString(parameters.string);
        }
        else if ("hexstring" in parameters) {
            this.fromHexString(parameters.hexstring);
        }
        else {
            if ("length" in parameters && parameters.length > 0) {
                this.length = parameters.length;
                if (parameters.stub) {
                    for (let i = 0; i < this._view.length; i++) {
                        this._view[i] = parameters.stub;
                    }
                }
            }
            else {
                this.length = 0;
            }
        }
    }
    set buffer(value) {
        this._buffer = value;
        this._view = new Uint8Array(this._buffer);
    }
    get buffer() {
        return this._buffer;
    }
    set view(value) {
        this._buffer = new ArrayBuffer(value.length);
        this._view = new Uint8Array(this._buffer);
        this._view.set(value);
    }
    get view() {
        return this._view;
    }
    get length() {
        return this.view.byteLength;
    }
    set length(value) {
        this._buffer = new ArrayBuffer(value);
        this._view = new Uint8Array(this._buffer);
    }
    clear() {
        this._buffer = new ArrayBuffer(0);
        this._view = new Uint8Array(this._buffer);
    }
    fromArrayBuffer(array) {
        this._buffer = array;
        this._view = new Uint8Array(this._buffer);
    }
    fromUint8Array(array) {
        this.fromArrayBuffer(new Uint8Array(array).buffer);
    }
    fromString(string) {
        const stringLength = string.length;
        this.length = stringLength;
        for (let i = 0; i < stringLength; i++)
            this.view[i] = string.charCodeAt(i);
    }
    toString(start = 0, length = (this.view.length - start)) {
        let result = "";
        if ((start >= this.view.length) || (start < 0)) {
            start = 0;
        }
        if ((length >= this.view.length) || (length < 0)) {
            length = this.view.length - start;
        }
        for (let i = start; i < (start + length); i++)
            result += String.fromCharCode(this.view[i]);
        return result;
    }
    fromHexString(hexString) {
        const stringLength = hexString.length;
        this.buffer = new ArrayBuffer(stringLength >> 1);
        this.view = new Uint8Array(this.buffer);
        const hexMap = new Map();
        hexMap.set("0", 0x00);
        hexMap.set("1", 0x01);
        hexMap.set("2", 0x02);
        hexMap.set("3", 0x03);
        hexMap.set("4", 0x04);
        hexMap.set("5", 0x05);
        hexMap.set("6", 0x06);
        hexMap.set("7", 0x07);
        hexMap.set("8", 0x08);
        hexMap.set("9", 0x09);
        hexMap.set("A", 0x0A);
        hexMap.set("a", 0x0A);
        hexMap.set("B", 0x0B);
        hexMap.set("b", 0x0B);
        hexMap.set("C", 0x0C);
        hexMap.set("c", 0x0C);
        hexMap.set("D", 0x0D);
        hexMap.set("d", 0x0D);
        hexMap.set("E", 0x0E);
        hexMap.set("e", 0x0E);
        hexMap.set("F", 0x0F);
        hexMap.set("f", 0x0F);
        let j = 0;
        let temp = 0x00;
        for (let i = 0; i < stringLength; i++) {
            if (!(i % 2)) {
                temp = hexMap.get(hexString.charAt(i)) << 4;
            }
            else {
                temp |= hexMap.get(hexString.charAt(i));
                this.view[j] = temp;
                j++;
            }
        }
    }
    toHexString(start = 0, length = (this.view.length - start)) {
        let result = "";
        if ((start >= this.view.length) || (start < 0)) {
            start = 0;
        }
        if ((length >= this.view.length) || (length < 0)) {
            length = this.view.length - start;
        }
        for (let i = start; i < (start + length); i++) {
            const str = this.view[i].toString(16).toUpperCase();
            result = result + ((str.length == 1) ? "0" : "") + str;
        }
        return result;
    }
    copy(start = 0, length = (this.length - start)) {
        if (!start && !this.length) {
            return new ByteStream();
        }
        if ((start < 0) || (start > (this.length - 1))) {
            throw new Error(`Wrong start position: ${start}`);
        }
        const stream = new ByteStream({
            buffer: this._buffer.slice(start, start + length)
        });
        return stream;
    }
    slice(start = 0, end = this.length) {
        if (!start && !this.length) {
            return new ByteStream();
        }
        if ((start < 0) || (start > (this.length - 1))) {
            throw new Error(`Wrong start position: ${start}`);
        }
        const stream = new ByteStream({
            buffer: this._buffer.slice(start, end),
        });
        return stream;
    }
    realloc(size) {
        const buffer = new ArrayBuffer(size);
        const view = new Uint8Array(buffer);
        if (size > this._view.length)
            view.set(this._view);
        else {
            view.set(new Uint8Array(this._buffer, 0, size));
        }
        this._buffer = buffer;
        this._view = new Uint8Array(this._buffer);
    }
    append(stream) {
        const initialSize = this.length;
        const streamViewLength = stream.length;
        const subarrayView = stream._view.subarray();
        this.realloc(initialSize + streamViewLength);
        this._view.set(subarrayView, initialSize);
    }
    insert(stream, start = 0, length = (this.length - start)) {
        if (start > (this.length - 1))
            return false;
        if (length > (this.length - start)) {
            length = this.length - start;
        }
        if (length > stream.length) {
            length = stream.length;
        }
        if (length == stream.length)
            this._view.set(stream._view, start);
        else {
            this._view.set(stream._view.subarray(0, length), start);
        }
        return true;
    }
    isEqual(stream) {
        if (this.length != stream.length)
            return false;
        for (let i = 0; i < stream.length; i++) {
            if (this.view[i] != stream.view[i])
                return false;
        }
        return true;
    }
    isEqualView(view) {
        if (view.length != this.view.length)
            return false;
        for (let i = 0; i < view.length; i++) {
            if (this.view[i] != view[i])
                return false;
        }
        return true;
    }
    findPattern(pattern, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const patternLength = pattern.length;
        if (patternLength > length) {
            return (-1);
        }
        const patternArray = [];
        for (let i = 0; i < patternLength; i++)
            patternArray.push(pattern.view[i]);
        for (let i = 0; i <= (length - patternLength); i++) {
            let equal = true;
            const equalStart = (backward) ? (start - patternLength - i) : (start + i);
            for (let j = 0; j < patternLength; j++) {
                if (this.view[j + equalStart] != patternArray[j]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                return (backward) ? (start - patternLength - i) : (start + patternLength + i);
            }
        }
        return (-1);
    }
    findFirstIn(patterns, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const result = {
            id: (-1),
            position: (backward) ? 0 : (start + length),
            length: 0
        };
        for (let i = 0; i < patterns.length; i++) {
            const position = this.findPattern(patterns[i], start, length, backward);
            if (position != (-1)) {
                let valid = false;
                const patternLength = patterns[i].length;
                if (backward) {
                    if ((position - patternLength) >= (result.position - result.length))
                        valid = true;
                }
                else {
                    if ((position - patternLength) <= (result.position - result.length))
                        valid = true;
                }
                if (valid) {
                    result.position = position;
                    result.id = i;
                    result.length = patternLength;
                }
            }
        }
        return result;
    }
    findAllIn(patterns, start_, length_) {
        let { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let patternFound = {
            id: (-1),
            position: start
        };
        do {
            const position = patternFound.position;
            patternFound = this.findFirstIn(patterns, patternFound.position, length);
            if (patternFound.id == (-1)) {
                break;
            }
            length -= (patternFound.position - position);
            result.push({
                id: patternFound.id,
                position: patternFound.position
            });
        } while (true);
        return result;
    }
    findAllPatternIn(pattern, start_, length_) {
        const { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        const patternLength = pattern.length;
        if (patternLength > length) {
            return (-1);
        }
        const patternArray = Array.from(pattern.view);
        for (let i = 0; i <= (length - patternLength); i++) {
            let equal = true;
            const equalStart = start + i;
            for (let j = 0; j < patternLength; j++) {
                if (this.view[j + equalStart] != patternArray[j]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                result.push(start + patternLength + i);
                i += (patternLength - 1);
            }
        }
        return result;
    }
    findFirstNotIn(patterns, start_, length_, backward_) {
        let { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const result = {
            left: {
                id: (-1),
                position: start
            },
            right: {
                id: (-1),
                position: 0
            },
            value: new ByteStream()
        };
        let currentLength = length;
        while (currentLength > 0) {
            result.right = this.findFirstIn(patterns, (backward) ? (start - length + currentLength) : (start + length - currentLength), currentLength, backward);
            if (result.right.id == (-1)) {
                length = currentLength;
                if (backward) {
                    start -= length;
                }
                else {
                    start = result.left.position;
                }
                result.value = new ByteStream({
                    buffer: this._buffer.slice(start, start + length),
                });
                break;
            }
            if (result.right.position != ((backward) ? (result.left.position - patterns[result.right.id].length) : (result.left.position + patterns[result.right.id].length))) {
                if (backward) {
                    start = result.right.position + patterns[result.right.id].length;
                    length = result.left.position - result.right.position - patterns[result.right.id].length;
                }
                else {
                    start = result.left.position;
                    length = result.right.position - result.left.position - patterns[result.right.id].length;
                }
                result.value = new ByteStream({
                    buffer: this._buffer.slice(start, start + length),
                });
                break;
            }
            result.left = result.right;
            currentLength -= patterns[result.right.id].length;
        }
        if (backward) {
            const temp = result.right;
            result.right = result.left;
            result.left = temp;
        }
        return result;
    }
    findAllNotIn(patterns, start_, length_) {
        let { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let patternFound = {
            left: {
                id: (-1),
                position: start
            },
            right: {
                id: (-1),
                position: start
            },
            value: new ByteStream()
        };
        do {
            const position = patternFound.right.position;
            patternFound = this.findFirstNotIn(patterns, patternFound.right.position, length);
            length -= (patternFound.right.position - position);
            result.push({
                left: {
                    id: patternFound.left.id,
                    position: patternFound.left.position
                },
                right: {
                    id: patternFound.right.id,
                    position: patternFound.right.position
                },
                value: patternFound.value
            });
        } while (patternFound.right.id != (-1));
        return result;
    }
    findFirstSequence(patterns, start_, length_, backward_) {
        let { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const firstIn = this.skipNotPatterns(patterns, start, length, backward);
        if (firstIn == (-1)) {
            return {
                position: (-1),
                value: new ByteStream()
            };
        }
        const firstNotIn = this.skipPatterns(patterns, firstIn, length - ((backward) ? (start - firstIn) : (firstIn - start)), backward);
        if (backward) {
            start = firstNotIn;
            length = (firstIn - firstNotIn);
        }
        else {
            start = firstIn;
            length = (firstNotIn - firstIn);
        }
        const value = new ByteStream({
            buffer: this._buffer.slice(start, start + length),
        });
        return {
            position: firstNotIn,
            value
        };
    }
    findAllSequences(patterns, start_, length_) {
        let { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let patternFound = {
            position: start,
            value: new ByteStream()
        };
        do {
            const position = patternFound.position;
            patternFound = this.findFirstSequence(patterns, patternFound.position, length);
            if (patternFound.position != (-1)) {
                length -= (patternFound.position - position);
                result.push({
                    position: patternFound.position,
                    value: patternFound.value,
                });
            }
        } while (patternFound.position != (-1));
        return result;
    }
    findPairedPatterns(leftPattern, rightPattern, start_, length_) {
        const result = [];
        if (leftPattern.isEqual(rightPattern))
            return result;
        const { start, length } = this.prepareFindParameters(start_, length_);
        let currentPositionLeft = 0;
        const leftPatterns = this.findAllPatternIn(leftPattern, start, length);
        if (!Array.isArray(leftPatterns) || leftPatterns.length == 0) {
            return result;
        }
        const rightPatterns = this.findAllPatternIn(rightPattern, start, length);
        if (!Array.isArray(rightPatterns) || rightPatterns.length == 0) {
            return result;
        }
        while (currentPositionLeft < leftPatterns.length) {
            if (rightPatterns.length == 0) {
                break;
            }
            if (leftPatterns[0] == rightPatterns[0]) {
                result.push({
                    left: leftPatterns[0],
                    right: rightPatterns[0]
                });
                leftPatterns.splice(0, 1);
                rightPatterns.splice(0, 1);
                continue;
            }
            if (leftPatterns[currentPositionLeft] > rightPatterns[0]) {
                break;
            }
            while (leftPatterns[currentPositionLeft] < rightPatterns[0]) {
                currentPositionLeft++;
                if (currentPositionLeft >= leftPatterns.length) {
                    break;
                }
            }
            result.push({
                left: leftPatterns[currentPositionLeft - 1],
                right: rightPatterns[0]
            });
            leftPatterns.splice(currentPositionLeft - 1, 1);
            rightPatterns.splice(0, 1);
            currentPositionLeft = 0;
        }
        result.sort((a, b) => (a.left - b.left));
        return result;
    }
    findPairedArrays(inputLeftPatterns, inputRightPatterns, start_, length_) {
        const { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let currentPositionLeft = 0;
        const leftPatterns = this.findAllIn(inputLeftPatterns, start, length);
        if (leftPatterns.length == 0)
            return result;
        const rightPatterns = this.findAllIn(inputRightPatterns, start, length);
        if (rightPatterns.length == 0)
            return result;
        while (currentPositionLeft < leftPatterns.length) {
            if (rightPatterns.length == 0) {
                break;
            }
            if (leftPatterns[0].position == rightPatterns[0].position) {
                result.push({
                    left: leftPatterns[0],
                    right: rightPatterns[0]
                });
                leftPatterns.splice(0, 1);
                rightPatterns.splice(0, 1);
                continue;
            }
            if (leftPatterns[currentPositionLeft].position > rightPatterns[0].position) {
                break;
            }
            while (leftPatterns[currentPositionLeft].position < rightPatterns[0].position) {
                currentPositionLeft++;
                if (currentPositionLeft >= leftPatterns.length) {
                    break;
                }
            }
            result.push({
                left: leftPatterns[currentPositionLeft - 1],
                right: rightPatterns[0]
            });
            leftPatterns.splice(currentPositionLeft - 1, 1);
            rightPatterns.splice(0, 1);
            currentPositionLeft = 0;
        }
        result.sort((a, b) => (a.left.position - b.left.position));
        return result;
    }
    replacePattern(searchPattern, replacePattern, start_, length_, findAllResult = null) {
        let result = [];
        let i;
        const output = {
            status: (-1),
            searchPatternPositions: [],
            replacePatternPositions: []
        };
        const { start, length } = this.prepareFindParameters(start_, length_);
        if (findAllResult == null) {
            result = this.findAllIn([searchPattern], start, length);
            if (result.length == 0) {
                return output;
            }
        }
        else {
            result = findAllResult;
        }
        output.searchPatternPositions.push(...Array.from(result, element => element.position));
        const patternDifference = searchPattern.length - replacePattern.length;
        const changedBuffer = new ArrayBuffer(this.view.length - (result.length * patternDifference));
        const changedView = new Uint8Array(changedBuffer);
        changedView.set(new Uint8Array(this.buffer, 0, start));
        for (i = 0; i < result.length; i++) {
            const currentPosition = (i == 0) ? start : result[i - 1].position;
            changedView.set(new Uint8Array(this.buffer, currentPosition, result[i].position - searchPattern.length - currentPosition), currentPosition - i * patternDifference);
            changedView.set(replacePattern.view, result[i].position - searchPattern.length - i * patternDifference);
            output.replacePatternPositions.push(result[i].position - searchPattern.length - i * patternDifference);
        }
        i--;
        changedView.set(new Uint8Array(this.buffer, result[i].position, this.length - result[i].position), result[i].position - searchPattern.length + replacePattern.length - i * patternDifference);
        this.buffer = changedBuffer;
        this.view = new Uint8Array(this.buffer);
        output.status = 1;
        return output;
    }
    skipPatterns(patterns, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        let result = start;
        for (let k = 0; k < patterns.length; k++) {
            const patternLength = patterns[k].length;
            const equalStart = (backward) ? (result - patternLength) : (result);
            let equal = true;
            for (let j = 0; j < patternLength; j++) {
                if (this.view[j + equalStart] != patterns[k].view[j]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                k = (-1);
                if (backward) {
                    result -= patternLength;
                    if (result <= 0)
                        return result;
                }
                else {
                    result += patternLength;
                    if (result >= (start + length))
                        return result;
                }
            }
        }
        return result;
    }
    skipNotPatterns(patterns, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        let result = (-1);
        for (let i = 0; i < length; i++) {
            for (let k = 0; k < patterns.length; k++) {
                const patternLength = patterns[k].length;
                const equalStart = (backward) ? (start - i - patternLength) : (start + i);
                let equal = true;
                for (let j = 0; j < patternLength; j++) {
                    if (this.view[j + equalStart] != patterns[k].view[j]) {
                        equal = false;
                        break;
                    }
                }
                if (equal) {
                    result = (backward) ? (start - i) : (start + i);
                    break;
                }
            }
            if (result != (-1)) {
                break;
            }
        }
        return result;
    }
    prepareFindParameters(start = null, length = null, backward = false) {
        if (start === null) {
            start = (backward) ? this.length : 0;
        }
        if (start > this.length) {
            start = this.length;
        }
        if (backward) {
            if (length === null) {
                length = start;
            }
            if (length > start) {
                length = start;
            }
        }
        else {
            if (length === null) {
                length = this.length - start;
            }
            if (length > (this.length - start)) {
                length = this.length - start;
            }
        }
        return { start, length, backward };
    }
}
exports.ByteStream = ByteStream;

},{}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseByteMap = void 0;
function parseByteMap(stream, map, elements, start = null, length = null) {
    if (start === null) {
        start = 0;
    }
    if (start > (stream.length - 1)) {
        return [];
    }
    if (length === null) {
        length = stream.length - start;
    }
    if (length > (stream.length - start)) {
        length = stream.length - start;
    }
    let dataView;
    if ((start == 0) && (length == stream.length)) {
        dataView = stream.view;
    }
    else {
        dataView = new Uint8Array(stream.buffer, start, length);
    }
    const resultArray = new Array(elements);
    let elementsCount = 0;
    let count = 0;
    const mapLength = map.length;
    while (count < length) {
        let structureLength = 0;
        resultArray[elementsCount] = {};
        for (let i = 0; i < mapLength; i++) {
            if (map[i].maxlength == 0) {
                if ("defaultValue" in map[i]) {
                    (resultArray[elementsCount])[map[i].name] = map[i].defaultValue;
                }
                continue;
            }
            const array = new Uint8Array(map[i].maxlength);
            for (let j = 0; j < map[i].maxlength; j++) {
                array[j] = dataView[count++];
            }
            const result = (map[i].func)(array);
            if (result.status == (-1)) {
                if (resultArray.length == 1) {
                    return [];
                }
                return resultArray.slice(0, resultArray.length - 1);
            }
            if (map[i].type != "check") {
                (resultArray[elementsCount])[map[i].name] = result.value;
            }
            count -= (map[i].maxlength - result.length);
            structureLength += result.length;
        }
        (resultArray[elementsCount++]).structureLength = structureLength;
    }
    return resultArray;
}
exports.parseByteMap = parseByteMap;

},{}],6:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./byte_stream"), exports);
__exportStar(require("./seq_stream"), exports);
__exportStar(require("./helpers"), exports);
__exportStar(require("./bit_stream"), exports);
__exportStar(require("./seq_bit_stream"), exports);

},{"./bit_stream":3,"./byte_stream":4,"./helpers":5,"./seq_bit_stream":7,"./seq_stream":8}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SeqBitStream = void 0;
const bit_stream_1 = require("./bit_stream");
class SeqBitStream {
    constructor(parameters = {}) {
        var _a;
        this._length = 0;
        this._start = 0;
        this.prevLength = 0;
        this.prevStart = 0;
        this.stream = ((_a = parameters.stream) === null || _a === void 0 ? void 0 : _a.slice()) || new bit_stream_1.BitStream();
        this.appendBlock = parameters.appendBlock || 0;
        if (parameters.start && parameters.start > 0) {
            this.start = parameters.start;
        }
        if (parameters.length && parameters.length > 0) {
            this.length = parameters.length;
        }
        this.backward = parameters.backward || false;
    }
    set start(value) {
        if (value > this.stream.bitsCount) {
            return;
        }
        this._length -= ((this.backward) ? (this._start - value) : (value - this._start));
        this._start = value;
        this.prevStart = this._start;
        this.prevLength = this._length;
    }
    get start() {
        return this._start;
    }
    set length(value) {
        if (value > this.stream.bitsCount) {
            return;
        }
        this.prevLength = this._length;
        this._length = value;
    }
    get length() {
        return this._length;
    }
    set stream(value) {
        this._stream = value;
        this.prevLength = this._length;
        this._length = value.bitsCount;
        this.prevStart = this._start;
        this._start = (this.backward) ? this.length : 0;
    }
    get stream() {
        return this._stream;
    }
    getBits(length = null) {
        if (length === null) {
            length = 0;
        }
        else if (length === 0) {
            return new bit_stream_1.BitStream();
        }
        if ((this.start + length) > this.stream.bitsCount) {
            length = (this.stream.bitsCount - this.start);
        }
        let result;
        if (this.backward) {
            result = this.stream.copy(this.start - length, length);
            this.start -= result.bitsCount;
        }
        else {
            result = this.stream.copy(this.start, length);
            this.start += result.bitsCount;
        }
        return result;
    }
    getBitsString(length) {
        return this.getBits(length).toString();
    }
    getBitsReversedValue(length) {
        const initialValue = this.getBitsString(length);
        const initialValueLength = initialValue.length;
        let byteIndex;
        const initialOffset = 8 - (initialValueLength % 8);
        const reversedValue = new Array(initialValueLength);
        const value = new Uint32Array(1);
        const valueView = new Uint8Array(value.buffer, 0, 4);
        let i;
        if (initialValueLength > 32) {
            return (-1);
        }
        if (length == 32) {
            byteIndex = 3;
        }
        else {
            byteIndex = ((initialValueLength - 1) >> 3);
        }
        for (i = 0; i < initialValueLength; i++) {
            reversedValue[initialValueLength - 1 - i] = initialValue[i];
        }
        for (i = initialOffset; i < (initialOffset + initialValueLength); i++) {
            if (reversedValue[i - initialOffset] == "1") {
                valueView[byteIndex] |= 0x01 << (7 - (i % 8));
            }
            if (i && (((i + 1) % 8) == 0)) {
                byteIndex--;
            }
        }
        return value[0];
    }
    toString() {
        const streamToDisplay = this.stream.copy(this.start, this.length);
        return streamToDisplay.toString();
    }
}
exports.SeqBitStream = SeqBitStream;

},{"./bit_stream":3}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SeqStream = void 0;
const byte_stream_1 = require("./byte_stream");
const pow2_24 = 16777216;
class SeqStream {
    constructor(parameters = {}) {
        this._stream = new byte_stream_1.ByteStream();
        this._length = 0;
        this._start = 0;
        this.backward = false;
        this.appendBlock = 0;
        this.prevLength = 0;
        this.prevStart = 0;
        if ("view" in parameters) {
            this.stream = new byte_stream_1.ByteStream({ view: parameters.view });
        }
        else if ("buffer" in parameters) {
            this.stream = new byte_stream_1.ByteStream({ buffer: parameters.buffer });
        }
        else if ("string" in parameters) {
            this.stream = new byte_stream_1.ByteStream({ string: parameters.string });
        }
        else if ("hexstring" in parameters) {
            this.stream = new byte_stream_1.ByteStream({ hexstring: parameters.hexstring });
        }
        else if ("stream" in parameters) {
            this.stream = parameters.stream.slice();
        }
        else {
            this.stream = new byte_stream_1.ByteStream();
        }
        if ("backward" in parameters && parameters.backward) {
            this.backward = parameters.backward;
            this._start = this.stream.length;
        }
        if ("length" in parameters && parameters.length > 0) {
            this._length = parameters.length;
        }
        if ("start" in parameters && parameters.start && parameters.start > 0) {
            this._start = parameters.start;
        }
        if ("appendBlock" in parameters && parameters.appendBlock && parameters.appendBlock > 0) {
            this.appendBlock = parameters.appendBlock;
        }
    }
    set stream(value) {
        this._stream = value;
        this.prevLength = this._length;
        this._length = value.length;
        this.prevStart = this._start;
        this._start = 0;
    }
    get stream() {
        return this._stream;
    }
    set length(value) {
        this.prevLength = this._length;
        this._length = value;
    }
    get length() {
        if (this.appendBlock) {
            return this.start;
        }
        return this._length;
    }
    set start(value) {
        if (value > this.stream.length)
            return;
        this.prevStart = this._start;
        this.prevLength = this._length;
        this._length -= (this.backward) ? (this._start - value) : (value - this._start);
        this._start = value;
    }
    get start() {
        return this._start;
    }
    get buffer() {
        return this._stream.buffer.slice(0, this._length);
    }
    resetPosition() {
        this._start = this.prevStart;
        this._length = this.prevLength;
    }
    findPattern(pattern, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const result = this.stream.findPattern(pattern, this.start, this.length, this.backward);
        if (result == (-1))
            return result;
        if (this.backward) {
            if (result < (this.start - pattern.length - gap)) {
                return (-1);
            }
        }
        else {
            if (result > (this.start + pattern.length + gap)) {
                return (-1);
            }
        }
        this.start = result;
        return result;
    }
    findFirstIn(patterns, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const result = this.stream.findFirstIn(patterns, this.start, this.length, this.backward);
        if (result.id == (-1))
            return result;
        if (this.backward) {
            if (result.position < (this.start - patterns[result.id].length - gap)) {
                return {
                    id: (-1),
                    position: (this.backward) ? 0 : (this.start + this.length)
                };
            }
        }
        else {
            if (result.position > (this.start + patterns[result.id].length + gap)) {
                return {
                    id: (-1),
                    position: (this.backward) ? 0 : (this.start + this.length)
                };
            }
        }
        this.start = result.position;
        return result;
    }
    findAllIn(patterns) {
        const start = (this.backward) ? (this.start - this.length) : this.start;
        return this.stream.findAllIn(patterns, start, this.length);
    }
    findFirstNotIn(patterns, gap = null) {
        if ((gap == null) || (gap > this._length)) {
            gap = this._length;
        }
        const result = this._stream.findFirstNotIn(patterns, this._start, this._length, this.backward);
        if ((result.left.id == (-1)) && (result.right.id == (-1))) {
            return result;
        }
        if (this.backward) {
            if (result.right.id != (-1)) {
                if (result.right.position < (this._start - patterns[result.right.id].length - gap)) {
                    return {
                        left: {
                            id: (-1),
                            position: this._start
                        },
                        right: {
                            id: (-1),
                            position: 0
                        },
                        value: new byte_stream_1.ByteStream()
                    };
                }
            }
        }
        else {
            if (result.left.id != (-1)) {
                if (result.left.position > (this._start + patterns[result.left.id].length + gap)) {
                    return {
                        left: {
                            id: (-1),
                            position: this._start
                        },
                        right: {
                            id: (-1),
                            position: 0
                        },
                        value: new byte_stream_1.ByteStream()
                    };
                }
            }
        }
        if (this.backward) {
            if (result.left.id == (-1)) {
                this.start = 0;
            }
            else {
                this.start = result.left.position;
            }
        }
        else {
            if (result.right.id == (-1)) {
                this.start = (this._start + this._length);
            }
            else {
                this.start = result.right.position;
            }
        }
        return result;
    }
    findAllNotIn(patterns) {
        const start = (this.backward) ? (this._start - this._length) : this._start;
        return this._stream.findAllNotIn(patterns, start, this._length);
    }
    findFirstSequence(patterns, length = null, gap = null) {
        if ((length == null) || (length > this._length)) {
            length = this._length;
        }
        if ((gap == null) || (gap > length)) {
            gap = length;
        }
        const result = this._stream.findFirstSequence(patterns, this._start, length, this.backward);
        if (result.value.length == 0) {
            return result;
        }
        if (this.backward) {
            if (result.position < (this._start - result.value.length - gap)) {
                return {
                    position: (-1),
                    value: new byte_stream_1.ByteStream()
                };
            }
        }
        else {
            if (result.position > (this._start + result.value.length + gap)) {
                return {
                    position: (-1),
                    value: new byte_stream_1.ByteStream()
                };
            }
        }
        this.start = result.position;
        return result;
    }
    findAllSequences(patterns) {
        const start = (this.backward) ? (this.start - this.length) : this.start;
        return this.stream.findAllSequences(patterns, start, this.length);
    }
    findPairedPatterns(leftPattern, rightPattern, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const start = (this.backward) ? (this.start - this.length) : this.start;
        const result = this.stream.findPairedPatterns(leftPattern, rightPattern, start, this.length);
        if (result.length) {
            if (this.backward) {
                if (result[0].right < (this.start - rightPattern.length - gap)) {
                    return [];
                }
            }
            else {
                if (result[0].left > (this.start + leftPattern.length + gap)) {
                    return [];
                }
            }
        }
        return result;
    }
    findPairedArrays(leftPatterns, rightPatterns, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const start = (this.backward) ? (this.start - this.length) : this.start;
        const result = this.stream.findPairedArrays(leftPatterns, rightPatterns, start, this.length);
        if (result.length) {
            if (this.backward) {
                if (result[0].right.position < (this.start - rightPatterns[result[0].right.id].length - gap)) {
                    return [];
                }
            }
            else {
                if (result[0].left.position > (this.start + leftPatterns[result[0].left.id].length + gap)) {
                    return [];
                }
            }
        }
        return result;
    }
    replacePattern(searchPattern, replacePattern) {
        const start = (this.backward) ? (this.start - this.length) : this.start;
        return this.stream.replacePattern(searchPattern, replacePattern, start, this.length);
    }
    skipPatterns(patterns) {
        const result = this.stream.skipPatterns(patterns, this.start, this.length, this.backward);
        this.start = result;
        return result;
    }
    skipNotPatterns(patterns) {
        const result = this.stream.skipNotPatterns(patterns, this.start, this.length, this.backward);
        if (result == (-1))
            return (-1);
        this.start = result;
        return result;
    }
    append(stream) {
        this.beforeAppend(stream.length);
        this._stream.view.set(stream.view, this._start);
        this._length += (stream.length * 2);
        this.start = (this._start + stream.length);
        this.prevLength -= (stream.length * 2);
    }
    appendView(view) {
        this.beforeAppend(view.length);
        this._stream.view.set(view, this._start);
        this._length += (view.length * 2);
        this.start = (this._start + view.length);
        this.prevLength -= (view.length * 2);
    }
    appendChar(char) {
        this.beforeAppend(1);
        this._stream.view[this._start] = char;
        this._length += 2;
        this.start = (this._start + 1);
        this.prevLength -= 2;
    }
    appendUint16(number) {
        this.beforeAppend(2);
        const value = new Uint16Array([number]);
        const view = new Uint8Array(value.buffer);
        this.stream.view[this._start] = view[1];
        this._stream.view[this._start + 1] = view[0];
        this._length += 4;
        this.start = this._start + 2;
        this.prevLength -= 4;
    }
    appendUint24(number) {
        this.beforeAppend(3);
        const value = new Uint32Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[2];
        this._stream.view[this._start + 1] = view[1];
        this._stream.view[this._start + 2] = view[0];
        this._length += 6;
        this.start = (this._start + 3);
        this.prevLength -= 6;
    }
    appendUint32(number) {
        this.beforeAppend(4);
        const value = new Uint32Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[3];
        this._stream.view[this._start + 1] = view[2];
        this._stream.view[this._start + 2] = view[1];
        this._stream.view[this._start + 3] = view[0];
        this._length += 8;
        this.start = (this._start + 4);
        this.prevLength -= 8;
    }
    appendInt16(number) {
        this.beforeAppend(2);
        const value = new Int16Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[1];
        this._stream.view[this._start + 1] = view[0];
        this._length += 4;
        this.start = (this._start + 2);
        this.prevLength -= 4;
    }
    appendInt32(number) {
        this.beforeAppend(4);
        const value = new Int32Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[3];
        this._stream.view[this._start + 1] = view[2];
        this._stream.view[this._start + 2] = view[1];
        this._stream.view[this._start + 3] = view[0];
        this._length += 8;
        this.start = (this._start + 4);
        this.prevLength -= 8;
    }
    getBlock(size, changeLength = true) {
        if (this._length <= 0) {
            return new Uint8Array(0);
        }
        if (this._length < size) {
            size = this._length;
        }
        let result;
        if (this.backward) {
            const view = this._stream.view.subarray(this._length - size, this._length);
            result = new Uint8Array(size);
            for (let i = 0; i < size; i++) {
                result[size - 1 - i] = view[i];
            }
        }
        else {
            result = this._stream.view.subarray(this._start, this._start + size);
        }
        if (changeLength) {
            this.start += ((this.backward) ? ((-1) * size) : size);
        }
        return result;
    }
    getUint16(changeLength = true) {
        const block = this.getBlock(2, changeLength);
        if (block.length < 2)
            return 0;
        return (block[0] << 8) | block[1];
    }
    getInt16(changeLength = true) {
        const num = this.getUint16(changeLength);
        const negative = 0x8000;
        if (num & negative) {
            return -(negative - (num ^ negative));
        }
        return num;
    }
    getUint24(changeLength = true) {
        const block = this.getBlock(4, changeLength);
        if (block.length < 3)
            return 0;
        return (block[0] << 16) |
            (block[1] << 8) |
            block[2];
    }
    getUint32(changeLength = true) {
        const block = this.getBlock(4, changeLength);
        if (block.length < 4)
            return 0;
        return (block[0] * pow2_24) +
            (block[1] << 16) +
            (block[2] << 8) +
            block[3];
    }
    getInt32(changeLength = true) {
        const num = this.getUint32(changeLength);
        const negative = 0x80000000;
        if (num & negative) {
            return -(negative - (num ^ negative));
        }
        return num;
    }
    beforeAppend(size) {
        if ((this._start + size) > this._stream.length) {
            if (size > this.appendBlock) {
                this.appendBlock = size + SeqStream.APPEND_BLOCK;
            }
            this._stream.realloc(this._stream.length + this.appendBlock);
        }
    }
}
exports.SeqStream = SeqStream;
SeqStream.APPEND_BLOCK = 1000;

},{"./byte_stream":4}],9:[function(require,module,exports){
(function (Buffer){
/*!
 * MIT License
 * 
 * Copyright (c) 2017-2024 Peculiar Ventures, LLC
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

'use strict';

const ARRAY_BUFFER_NAME = "[object ArrayBuffer]";
class BufferSourceConverter {
    static isArrayBuffer(data) {
        return Object.prototype.toString.call(data) === ARRAY_BUFFER_NAME;
    }
    static toArrayBuffer(data) {
        if (this.isArrayBuffer(data)) {
            return data;
        }
        if (data.byteLength === data.buffer.byteLength) {
            return data.buffer;
        }
        if (data.byteOffset === 0 && data.byteLength === data.buffer.byteLength) {
            return data.buffer;
        }
        return this.toUint8Array(data.buffer)
            .slice(data.byteOffset, data.byteOffset + data.byteLength)
            .buffer;
    }
    static toUint8Array(data) {
        return this.toView(data, Uint8Array);
    }
    static toView(data, type) {
        if (data.constructor === type) {
            return data;
        }
        if (this.isArrayBuffer(data)) {
            return new type(data);
        }
        if (this.isArrayBufferView(data)) {
            return new type(data.buffer, data.byteOffset, data.byteLength);
        }
        throw new TypeError("The provided value is not of type '(ArrayBuffer or ArrayBufferView)'");
    }
    static isBufferSource(data) {
        return this.isArrayBufferView(data)
            || this.isArrayBuffer(data);
    }
    static isArrayBufferView(data) {
        return ArrayBuffer.isView(data)
            || (data && this.isArrayBuffer(data.buffer));
    }
    static isEqual(a, b) {
        const aView = BufferSourceConverter.toUint8Array(a);
        const bView = BufferSourceConverter.toUint8Array(b);
        if (aView.length !== bView.byteLength) {
            return false;
        }
        for (let i = 0; i < aView.length; i++) {
            if (aView[i] !== bView[i]) {
                return false;
            }
        }
        return true;
    }
    static concat(...args) {
        let buffers;
        if (Array.isArray(args[0]) && !(args[1] instanceof Function)) {
            buffers = args[0];
        }
        else if (Array.isArray(args[0]) && args[1] instanceof Function) {
            buffers = args[0];
        }
        else {
            if (args[args.length - 1] instanceof Function) {
                buffers = args.slice(0, args.length - 1);
            }
            else {
                buffers = args;
            }
        }
        let size = 0;
        for (const buffer of buffers) {
            size += buffer.byteLength;
        }
        const res = new Uint8Array(size);
        let offset = 0;
        for (const buffer of buffers) {
            const view = this.toUint8Array(buffer);
            res.set(view, offset);
            offset += view.length;
        }
        if (args[args.length - 1] instanceof Function) {
            return this.toView(res, args[args.length - 1]);
        }
        return res.buffer;
    }
}

const STRING_TYPE = "string";
const HEX_REGEX = /^[0-9a-f\s]+$/i;
const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_REGEX = /^[a-zA-Z0-9-_]+$/;
class Utf8Converter {
    static fromString(text) {
        const s = unescape(encodeURIComponent(text));
        const uintArray = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) {
            uintArray[i] = s.charCodeAt(i);
        }
        return uintArray.buffer;
    }
    static toString(buffer) {
        const buf = BufferSourceConverter.toUint8Array(buffer);
        let encodedString = "";
        for (let i = 0; i < buf.length; i++) {
            encodedString += String.fromCharCode(buf[i]);
        }
        const decodedString = decodeURIComponent(escape(encodedString));
        return decodedString;
    }
}
class Utf16Converter {
    static toString(buffer, littleEndian = false) {
        const arrayBuffer = BufferSourceConverter.toArrayBuffer(buffer);
        const dataView = new DataView(arrayBuffer);
        let res = "";
        for (let i = 0; i < arrayBuffer.byteLength; i += 2) {
            const code = dataView.getUint16(i, littleEndian);
            res += String.fromCharCode(code);
        }
        return res;
    }
    static fromString(text, littleEndian = false) {
        const res = new ArrayBuffer(text.length * 2);
        const dataView = new DataView(res);
        for (let i = 0; i < text.length; i++) {
            dataView.setUint16(i * 2, text.charCodeAt(i), littleEndian);
        }
        return res;
    }
}
class Convert {
    static isHex(data) {
        return typeof data === STRING_TYPE
            && HEX_REGEX.test(data);
    }
    static isBase64(data) {
        return typeof data === STRING_TYPE
            && BASE64_REGEX.test(data);
    }
    static isBase64Url(data) {
        return typeof data === STRING_TYPE
            && BASE64URL_REGEX.test(data);
    }
    static ToString(buffer, enc = "utf8") {
        const buf = BufferSourceConverter.toUint8Array(buffer);
        switch (enc.toLowerCase()) {
            case "utf8":
                return this.ToUtf8String(buf);
            case "binary":
                return this.ToBinary(buf);
            case "hex":
                return this.ToHex(buf);
            case "base64":
                return this.ToBase64(buf);
            case "base64url":
                return this.ToBase64Url(buf);
            case "utf16le":
                return Utf16Converter.toString(buf, true);
            case "utf16":
            case "utf16be":
                return Utf16Converter.toString(buf);
            default:
                throw new Error(`Unknown type of encoding '${enc}'`);
        }
    }
    static FromString(str, enc = "utf8") {
        if (!str) {
            return new ArrayBuffer(0);
        }
        switch (enc.toLowerCase()) {
            case "utf8":
                return this.FromUtf8String(str);
            case "binary":
                return this.FromBinary(str);
            case "hex":
                return this.FromHex(str);
            case "base64":
                return this.FromBase64(str);
            case "base64url":
                return this.FromBase64Url(str);
            case "utf16le":
                return Utf16Converter.fromString(str, true);
            case "utf16":
            case "utf16be":
                return Utf16Converter.fromString(str);
            default:
                throw new Error(`Unknown type of encoding '${enc}'`);
        }
    }
    static ToBase64(buffer) {
        const buf = BufferSourceConverter.toUint8Array(buffer);
        if (typeof btoa !== "undefined") {
            const binary = this.ToString(buf, "binary");
            return btoa(binary);
        }
        else {
            return Buffer.from(buf).toString("base64");
        }
    }
    static FromBase64(base64) {
        const formatted = this.formatString(base64);
        if (!formatted) {
            return new ArrayBuffer(0);
        }
        if (!Convert.isBase64(formatted)) {
            throw new TypeError("Argument 'base64Text' is not Base64 encoded");
        }
        if (typeof atob !== "undefined") {
            return this.FromBinary(atob(formatted));
        }
        else {
            return new Uint8Array(Buffer.from(formatted, "base64")).buffer;
        }
    }
    static FromBase64Url(base64url) {
        const formatted = this.formatString(base64url);
        if (!formatted) {
            return new ArrayBuffer(0);
        }
        if (!Convert.isBase64Url(formatted)) {
            throw new TypeError("Argument 'base64url' is not Base64Url encoded");
        }
        return this.FromBase64(this.Base64Padding(formatted.replace(/\-/g, "+").replace(/\_/g, "/")));
    }
    static ToBase64Url(data) {
        return this.ToBase64(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
    }
    static FromUtf8String(text, encoding = Convert.DEFAULT_UTF8_ENCODING) {
        switch (encoding) {
            case "ascii":
                return this.FromBinary(text);
            case "utf8":
                return Utf8Converter.fromString(text);
            case "utf16":
            case "utf16be":
                return Utf16Converter.fromString(text);
            case "utf16le":
            case "usc2":
                return Utf16Converter.fromString(text, true);
            default:
                throw new Error(`Unknown type of encoding '${encoding}'`);
        }
    }
    static ToUtf8String(buffer, encoding = Convert.DEFAULT_UTF8_ENCODING) {
        switch (encoding) {
            case "ascii":
                return this.ToBinary(buffer);
            case "utf8":
                return Utf8Converter.toString(buffer);
            case "utf16":
            case "utf16be":
                return Utf16Converter.toString(buffer);
            case "utf16le":
            case "usc2":
                return Utf16Converter.toString(buffer, true);
            default:
                throw new Error(`Unknown type of encoding '${encoding}'`);
        }
    }
    static FromBinary(text) {
        const stringLength = text.length;
        const resultView = new Uint8Array(stringLength);
        for (let i = 0; i < stringLength; i++) {
            resultView[i] = text.charCodeAt(i);
        }
        return resultView.buffer;
    }
    static ToBinary(buffer) {
        const buf = BufferSourceConverter.toUint8Array(buffer);
        let res = "";
        for (let i = 0; i < buf.length; i++) {
            res += String.fromCharCode(buf[i]);
        }
        return res;
    }
    static ToHex(buffer) {
        const buf = BufferSourceConverter.toUint8Array(buffer);
        let result = "";
        const len = buf.length;
        for (let i = 0; i < len; i++) {
            const byte = buf[i];
            if (byte < 16) {
                result += "0";
            }
            result += byte.toString(16);
        }
        return result;
    }
    static FromHex(hexString) {
        let formatted = this.formatString(hexString);
        if (!formatted) {
            return new ArrayBuffer(0);
        }
        if (!Convert.isHex(formatted)) {
            throw new TypeError("Argument 'hexString' is not HEX encoded");
        }
        if (formatted.length % 2) {
            formatted = `0${formatted}`;
        }
        const res = new Uint8Array(formatted.length / 2);
        for (let i = 0; i < formatted.length; i = i + 2) {
            const c = formatted.slice(i, i + 2);
            res[i / 2] = parseInt(c, 16);
        }
        return res.buffer;
    }
    static ToUtf16String(buffer, littleEndian = false) {
        return Utf16Converter.toString(buffer, littleEndian);
    }
    static FromUtf16String(text, littleEndian = false) {
        return Utf16Converter.fromString(text, littleEndian);
    }
    static Base64Padding(base64) {
        const padCount = 4 - (base64.length % 4);
        if (padCount < 4) {
            for (let i = 0; i < padCount; i++) {
                base64 += "=";
            }
        }
        return base64;
    }
    static formatString(data) {
        return (data === null || data === void 0 ? void 0 : data.replace(/[\n\r\t ]/g, "")) || "";
    }
}
Convert.DEFAULT_UTF8_ENCODING = "utf8";

function assign(target, ...sources) {
    const res = arguments[0];
    for (let i = 1; i < arguments.length; i++) {
        const obj = arguments[i];
        for (const prop in obj) {
            res[prop] = obj[prop];
        }
    }
    return res;
}
function combine(...buf) {
    const totalByteLength = buf.map((item) => item.byteLength).reduce((prev, cur) => prev + cur);
    const res = new Uint8Array(totalByteLength);
    let currentPos = 0;
    buf.map((item) => new Uint8Array(item)).forEach((arr) => {
        for (const item2 of arr) {
            res[currentPos++] = item2;
        }
    });
    return res.buffer;
}
function isEqual(bytes1, bytes2) {
    if (!(bytes1 && bytes2)) {
        return false;
    }
    if (bytes1.byteLength !== bytes2.byteLength) {
        return false;
    }
    const b1 = new Uint8Array(bytes1);
    const b2 = new Uint8Array(bytes2);
    for (let i = 0; i < bytes1.byteLength; i++) {
        if (b1[i] !== b2[i]) {
            return false;
        }
    }
    return true;
}

exports.BufferSourceConverter = BufferSourceConverter;
exports.Convert = Convert;
exports.assign = assign;
exports.combine = combine;
exports.isEqual = isEqual;

}).call(this,require("buffer").Buffer)
},{"buffer":13}],10:[function(require,module,exports){
/*!
 Copyright (c) Peculiar Ventures, LLC
*/

'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function getUTCDate(date) {

    return new Date(date.getTime() + (date.getTimezoneOffset() * 60000));

}

function getParametersValue(parameters, name, defaultValue) {

    var _a;

    if ((parameters instanceof Object) === false) {

        return defaultValue;

    }

    return (_a = parameters[name]) !== null && _a !== void 0 ? _a : defaultValue;

}

function bufferToHexCodes(inputBuffer, inputOffset = 0, inputLength = (inputBuffer.byteLength - inputOffset), insertSpace = false) {

    let result = "";

    for (const item of (new Uint8Array(inputBuffer, inputOffset, inputLength))) {

        const str = item.toString(16).toUpperCase();

        if (str.length === 1) {

            result += "0";

        }

        result += str;

        if (insertSpace) {

            result += " ";

        }

    }

    return result.trim();

}

function checkBufferParams(baseBlock, inputBuffer, inputOffset, inputLength) {

    if (!(inputBuffer instanceof ArrayBuffer)) {

        baseBlock.error = "Wrong parameter: inputBuffer must be \"ArrayBuffer\"";

        return false;

    }

    if (!inputBuffer.byteLength) {

        baseBlock.error = "Wrong parameter: inputBuffer has zero length";

        return false;

    }

    if (inputOffset < 0) {

        baseBlock.error = "Wrong parameter: inputOffset less than zero";

        return false;

    }

    if (inputLength < 0) {

        baseBlock.error = "Wrong parameter: inputLength less than zero";

        return false;

    }

    if ((inputBuffer.byteLength - inputOffset - inputLength) < 0) {

        baseBlock.error = "End of input reached before message was fully decoded (inconsistent offset and length values)";

        return false;

    }

    return true;

}

function utilFromBase(inputBuffer, inputBase) {

    let result = 0;

    if (inputBuffer.length === 1) {

        return inputBuffer[0];

    }

    for (let i = (inputBuffer.length - 1); i >= 0; i--) {

        result += inputBuffer[(inputBuffer.length - 1) - i] * Math.pow(2, inputBase * i);

    }

    return result;

}

function utilToBase(value, base, reserved = (-1)) {

    const internalReserved = reserved;

    let internalValue = value;

    let result = 0;

    let biggest = Math.pow(2, base);

    for (let i = 1; i < 8; i++) {

        if (value < biggest) {

            let retBuf;

            if (internalReserved < 0) {

                retBuf = new ArrayBuffer(i);

                result = i;

            }

            else {

                if (internalReserved < i) {

                    return (new ArrayBuffer(0));

                }

                retBuf = new ArrayBuffer(internalReserved);

                result = internalReserved;

            }

            const retView = new Uint8Array(retBuf);

            for (let j = (i - 1); j >= 0; j--) {

                const basis = Math.pow(2, j * base);

                retView[result - j - 1] = Math.floor(internalValue / basis);

                internalValue -= (retView[result - j - 1]) * basis;

            }

            return retBuf;

        }

        biggest *= Math.pow(2, base);

    }

    return new ArrayBuffer(0);

}

function utilConcatBuf(...buffers) {

    let outputLength = 0;

    let prevLength = 0;

    for (const buffer of buffers) {

        outputLength += buffer.byteLength;

    }

    const retBuf = new ArrayBuffer(outputLength);

    const retView = new Uint8Array(retBuf);

    for (const buffer of buffers) {

        retView.set(new Uint8Array(buffer), prevLength);

        prevLength += buffer.byteLength;

    }

    return retBuf;

}

function utilConcatView(...views) {

    let outputLength = 0;

    let prevLength = 0;

    for (const view of views) {

        outputLength += view.length;

    }

    const retBuf = new ArrayBuffer(outputLength);

    const retView = new Uint8Array(retBuf);

    for (const view of views) {

        retView.set(view, prevLength);

        prevLength += view.length;

    }

    return retView;

}

function utilDecodeTC() {

    const buf = new Uint8Array(this.valueHex);

    if (this.valueHex.byteLength >= 2) {

        const condition1 = (buf[0] === 0xFF) && (buf[1] & 0x80);

        const condition2 = (buf[0] === 0x00) && ((buf[1] & 0x80) === 0x00);

        if (condition1 || condition2) {

            this.warnings.push("Needlessly long format");

        }

    }

    const bigIntBuffer = new ArrayBuffer(this.valueHex.byteLength);

    const bigIntView = new Uint8Array(bigIntBuffer);

    for (let i = 0; i < this.valueHex.byteLength; i++) {

        bigIntView[i] = 0;

    }

    bigIntView[0] = (buf[0] & 0x80);

    const bigInt = utilFromBase(bigIntView, 8);

    const smallIntBuffer = new ArrayBuffer(this.valueHex.byteLength);

    const smallIntView = new Uint8Array(smallIntBuffer);

    for (let j = 0; j < this.valueHex.byteLength; j++) {

        smallIntView[j] = buf[j];

    }

    smallIntView[0] &= 0x7F;

    const smallInt = utilFromBase(smallIntView, 8);

    return (smallInt - bigInt);

}

function utilEncodeTC(value) {

    const modValue = (value < 0) ? (value * (-1)) : value;

    let bigInt = 128;

    for (let i = 1; i < 8; i++) {

        if (modValue <= bigInt) {

            if (value < 0) {

                const smallInt = bigInt - modValue;

                const retBuf = utilToBase(smallInt, 8, i);

                const retView = new Uint8Array(retBuf);

                retView[0] |= 0x80;

                return retBuf;

            }

            let retBuf = utilToBase(modValue, 8, i);

            let retView = new Uint8Array(retBuf);

            if (retView[0] & 0x80) {

                const tempBuf = retBuf.slice(0);

                const tempView = new Uint8Array(tempBuf);

                retBuf = new ArrayBuffer(retBuf.byteLength + 1);

                retView = new Uint8Array(retBuf);

                for (let k = 0; k < tempBuf.byteLength; k++) {

                    retView[k + 1] = tempView[k];

                }

                retView[0] = 0x00;

            }

            return retBuf;

        }

        bigInt *= Math.pow(2, 8);

    }

    return (new ArrayBuffer(0));

}

function isEqualBuffer(inputBuffer1, inputBuffer2) {

    if (inputBuffer1.byteLength !== inputBuffer2.byteLength) {

        return false;

    }

    const view1 = new Uint8Array(inputBuffer1);

    const view2 = new Uint8Array(inputBuffer2);

    for (let i = 0; i < view1.length; i++) {

        if (view1[i] !== view2[i]) {

            return false;

        }

    }

    return true;

}

function padNumber(inputNumber, fullLength) {

    const str = inputNumber.toString(10);

    if (fullLength < str.length) {

        return "";

    }

    const dif = fullLength - str.length;

    const padding = new Array(dif);

    for (let i = 0; i < dif; i++) {

        padding[i] = "0";

    }

    const paddingString = padding.join("");

    return paddingString.concat(str);

}

const base64Template = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

const base64UrlTemplate = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";

function toBase64(input, useUrlTemplate = false, skipPadding = false, skipLeadingZeros = false) {

    let i = 0;

    let flag1 = 0;

    let flag2 = 0;

    let output = "";

    const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;

    if (skipLeadingZeros) {

        let nonZeroPosition = 0;

        for (let i = 0; i < input.length; i++) {

            if (input.charCodeAt(i) !== 0) {

                nonZeroPosition = i;

                break;

            }

        }

        input = input.slice(nonZeroPosition);

    }

    while (i < input.length) {

        const chr1 = input.charCodeAt(i++);

        if (i >= input.length) {

            flag1 = 1;

        }

        const chr2 = input.charCodeAt(i++);

        if (i >= input.length) {

            flag2 = 1;

        }

        const chr3 = input.charCodeAt(i++);

        const enc1 = chr1 >> 2;

        const enc2 = ((chr1 & 0x03) << 4) | (chr2 >> 4);

        let enc3 = ((chr2 & 0x0F) << 2) | (chr3 >> 6);

        let enc4 = chr3 & 0x3F;

        if (flag1 === 1) {

            enc3 = enc4 = 64;

        }

        else {

            if (flag2 === 1) {

                enc4 = 64;

            }

        }

        if (skipPadding) {

            if (enc3 === 64) {

                output += `${template.charAt(enc1)}${template.charAt(enc2)}`;

            }

            else {

                if (enc4 === 64) {

                    output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}`;

                }

                else {

                    output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;

                }

            }

        }

        else {

            output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;

        }

    }

    return output;

}

function fromBase64(input, useUrlTemplate = false, cutTailZeros = false) {

    const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;

    function indexOf(toSearch) {

        for (let i = 0; i < 64; i++) {

            if (template.charAt(i) === toSearch)

                return i;

        }

        return 64;

    }

    function test(incoming) {

        return ((incoming === 64) ? 0x00 : incoming);

    }

    let i = 0;

    let output = "";

    while (i < input.length) {

        const enc1 = indexOf(input.charAt(i++));

        const enc2 = (i >= input.length) ? 0x00 : indexOf(input.charAt(i++));

        const enc3 = (i >= input.length) ? 0x00 : indexOf(input.charAt(i++));

        const enc4 = (i >= input.length) ? 0x00 : indexOf(input.charAt(i++));

        const chr1 = (test(enc1) << 2) | (test(enc2) >> 4);

        const chr2 = ((test(enc2) & 0x0F) << 4) | (test(enc3) >> 2);

        const chr3 = ((test(enc3) & 0x03) << 6) | test(enc4);

        output += String.fromCharCode(chr1);

        if (enc3 !== 64) {

            output += String.fromCharCode(chr2);

        }

        if (enc4 !== 64) {

            output += String.fromCharCode(chr3);

        }

    }

    if (cutTailZeros) {

        const outputLength = output.length;

        let nonZeroStart = (-1);

        for (let i = (outputLength - 1); i >= 0; i--) {

            if (output.charCodeAt(i) !== 0) {

                nonZeroStart = i;

                break;

            }

        }

        if (nonZeroStart !== (-1)) {

            output = output.slice(0, nonZeroStart + 1);

        }

        else {

            output = "";

        }

    }

    return output;

}

function arrayBufferToString(buffer) {

    let resultString = "";

    const view = new Uint8Array(buffer);

    for (const element of view) {

        resultString += String.fromCharCode(element);

    }

    return resultString;

}

function stringToArrayBuffer(str) {

    const stringLength = str.length;

    const resultBuffer = new ArrayBuffer(stringLength);

    const resultView = new Uint8Array(resultBuffer);

    for (let i = 0; i < stringLength; i++) {

        resultView[i] = str.charCodeAt(i);

    }

    return resultBuffer;

}

const log2 = Math.log(2);

function nearestPowerOf2(length) {

    const base = (Math.log(length) / log2);

    const floor = Math.floor(base);

    const round = Math.round(base);

    return ((floor === round) ? floor : round);

}

function clearProps(object, propsArray) {

    for (const prop of propsArray) {

        delete object[prop];

    }

}

exports.arrayBufferToString = arrayBufferToString;
exports.bufferToHexCodes = bufferToHexCodes;
exports.checkBufferParams = checkBufferParams;
exports.clearProps = clearProps;
exports.fromBase64 = fromBase64;
exports.getParametersValue = getParametersValue;
exports.getUTCDate = getUTCDate;
exports.isEqualBuffer = isEqualBuffer;
exports.nearestPowerOf2 = nearestPowerOf2;
exports.padNumber = padNumber;
exports.stringToArrayBuffer = stringToArrayBuffer;
exports.toBase64 = toBase64;
exports.utilConcatBuf = utilConcatBuf;
exports.utilConcatView = utilConcatView;
exports.utilDecodeTC = utilDecodeTC;
exports.utilEncodeTC = utilEncodeTC;
exports.utilFromBase = utilFromBase;
exports.utilToBase = utilToBase;

},{}],11:[function(require,module,exports){
const asn1js = require("asn1js");
const pvtsutils = require("pvtsutils");
const bytestreamjs = require("bytestreamjs");
const pvutils = require("pvutils");
module.exports = {
  asn1js: asn1js,
  pvtsutils:pvtsutils,
  bytestreamjs:bytestreamjs,
  pvutils:pvutils
}
  
export_asn1js = asn1js;
export_pvtsutils = pvtsutils;
export_bytestreamjs = bytestreamjs;
export_pvutils = pvutils;

},{"asn1js":1,"bytestreamjs":6,"pvtsutils":9,"pvutils":10}],12:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  for (var i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(
      uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
    ))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],13:[function(require,module,exports){
(function (Buffer){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

}).call(this,require("buffer").Buffer)
},{"base64-js":12,"buffer":13,"ieee754":14}],14:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}]},{},[11]);

export default {
  asn1js:export_asn1js,
  pvtsutils:export_pvtsutils,
  bytestreamjs:export_bytestreamjs,
  pvutils:export_pvutils
}