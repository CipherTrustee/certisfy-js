let export_bytestreamjs;

(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
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

},{}],2:[function(require,module,exports){
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

},{"./bit":1,"./byte_stream":3}],3:[function(require,module,exports){
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

},{}],4:[function(require,module,exports){
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

},{}],5:[function(require,module,exports){
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

},{"./bit_stream":2,"./byte_stream":3,"./helpers":4,"./seq_bit_stream":6,"./seq_stream":7}],6:[function(require,module,exports){
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

},{"./bit_stream":2}],7:[function(require,module,exports){
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

},{"./byte_stream":3}],8:[function(require,module,exports){
const bytestreamjs = require("bytestreamjs");
module.exports = {
  bytestreamjs:bytestreamjs
}
export_bytestreamjs = bytestreamjs;
  
},{"bytestreamjs":5}]},{},[8]);

export default {bytestreamjs:export_bytestreamjs};