//대칭키 암호화
//https://www.npmjs.com/package/aes-js 참고
var aesjs = require('aes-js');


var CTR_Counter = function(key,text,Counter_num){//CTR-Counter

  //암호화

  //text -> textBytes
  let textBytes = aesjs.utils.utf8.toBytes(text);
  console.log("commome textBytes : ",textBytes);

  // The counter is optional, and if omitted will begin at 1
  //Counter => 시행 횟수 조정 아래 해독할 때 카운트랑 동일하게 해줘야함
  let aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(Counter_num));
  let encryptedBytes = aesCtr.encrypt(textBytes);
  console.log("encrypt textBytes : ",encryptedBytes);

  // To print or store the binary data, you may convert it to hex
  //textBytes => text
  let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
  console.log(encryptedHex);
  // "a338eda3874ed884b6199150d36f49988c90f5c47fe7792b0cf8c7f77eeffd87
  //  ea145b73e82aefcf2076f881c88879e4e25b1d7b24ba2788"


  //여기서부터 복호화

  // When ready to decrypt the hex string, convert it back to bytes
  //text -> textBytes
  encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

  // The counter mode of operation maintains internal state, so to
  // decrypt a new instance must be instantiated.
  //Counter => 시행 횟수 조정 위에 암호화할 때 카운트랑 동일하게 해줘야함
  aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(Counter_num));
  let decryptedBytes = aesCtr.decrypt(encryptedBytes);

    //textBytes => text
  var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  console.log(decryptedText);
  // "Text may be any length you wish, no padding is required."
}

var CBC = function(key,text,iv){

  let textBytes = aesjs.utils.utf8.toBytes(text);
  let aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
  let encryptedBytes = aesCbc.encrypt(textBytes);

  // To print or store the binary data, you may convert it to hex
  let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
  console.log(encryptedHex);
  // "104fb073f9a131f2cab49184bb864ca2"

  // When ready to decrypt the hex string, convert it back to bytes
  encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

  // The cipher-block chaining mode of operation maintains internal
  // state, so to decrypt a new instance must be instantiated.
  aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
  let decryptedBytes = aesCbc.decrypt(encryptedBytes);

  // Convert our bytes back into text
  let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  console.log(decryptedText);
}

var CFB = function(key,text,iv,segmentSize){

  let textBytes = aesjs.utils.utf8.toBytes(text);


  let aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segmentSize);
  let encryptedBytes = aesCfb.encrypt(textBytes);

  // To print or store the binary data, you may convert it to hex
  let encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
  console.log(encryptedHex);
  // "55e3af2638c560b4fdb9d26a630733ea60197ec23deb85b1f60f71f10409ce27"

  // When ready to decrypt the hex string, convert it back to bytes
  encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex);

  // The cipher feedback mode of operation maintains internal state,
  // so to decrypt a new instance must be instantiated.
  aesCfb = new aesjs.ModeOfOperation.cfb(key, iv, segmentSize);
  let decryptedBytes = aesCfb.decrypt(encryptedBytes);

  // Convert our bytes back into text
  let decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  console.log(decryptedText);
  // "TextMustBeAMultipleOfSegmentSize"
}

// An example 128-bit key (16 bytes * 8 bits/byte = 128 bits)
//128 192 256 선택 가능
let set_key = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 ];
// Convert text to bytes
let plain_text = 'Text may';
//operation count
let counter_num = 5
CTR_Counter(set_key,plain_text,5);
console.log("");

//CBC 방식에서 평문은 16bytes의 배수여야 한다.
var CBC_text = 'TextMustBe16Byte';
// The initialization vector (must be 16 bytes)
var iv_text = [ 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,35, 36 ];
CBC(set_key,CBC_text,iv_text);
console.log("");

// Convert text to bytes (must be a multiple of the segment size you choose below)
var CFB_text = 'TextMustBeAMultipleOfSegmentSize';
// The segment size is optional, and defaults to 1
// 평문이 segment_Size의 배수여야 한다.
//https://security.stackexchange.com/questions/85727/what-is-the-segment-size-when-using-cipher-feedback-cfb-chaining-mode 참고
var segment_Size = 8;
CFB(set_key,CFB_text,iv_text,segment_Size);
console.log("");

//rainbow attack 대비용 salting 기능이 포함된 비밀번호 알고리즘
//https://www.npmjs.com/package/pbkdf2 참고
//https://d2.naver.com/helloworld/318732 참고
var pbkdf2 = require('pbkdf2');
var key_128 = pbkdf2.pbkdf2Sync('password_test', 'salt_test', 1, 128 / 8, 'sha512');
var key_192 = pbkdf2.pbkdf2Sync('password', 'salt', 1, 192 / 8, 'sha512');
var key_256 = pbkdf2.pbkdf2Sync('password', 'salt', 1, 256 / 8, 'sha512');
console.log(key_128);
console.log(key_192);
console.log(key_256);
console.log("");

CFB(key_256,CFB_text,iv_text,segment_Size);
console.log("");
