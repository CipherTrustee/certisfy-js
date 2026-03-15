    import * as asn1js from './crypto/asn1js.js';
    import * as pkijs from './crypto/pkijs.es.js';
    import * as hmacUtil from './crypto/hmac-util.js';
    import * as pvtsutils from './crypto/pvtsutils.js';

    let dhParams = null;
    
    //AES-CBC paramaters
    const   CBC_HMAC_LENGTH 			= 32;//in bytes
    const   CBC_HALF_HMAC_LENGTH 		= 16;//in bytes
    const   CBC_IV_LENGTH 				= 16;//in bytes
    const 	CBC_PADDING					= "PKCS5Padding";//same as PKCS7Padding
    
    //AES-GCM parameters
    const 	GCM_NONCE_LENGTH 			= 12; // in bytes
    const 	GCM_TAG_LENGTH 				= 16; // in bytes	
  	const 	GCM_PADDING 				= "NoPadding";
    
    const   AES_KEY_SIZE				= 128;
	const	BYTE_SIZE					= 8;
	const   HMAC_LENGTH					= 32;//in bytes

	const   _CURVE_J2JS					= {"secp256r1":"P-256","secp384r1":"P-384","secp521r1":"P-521"};

    function CURVE_J2JS(c){
       return _CURVE_J2JS[c]? _CURVE_J2JS[c]:c;
    }

	function setDHParams(params){
      dhParams = params;
    }

	function getDHParams(){
     	return dhParams; 
    }
		
    function randomUUID(){      
        return window.crypto.randomUUID().replaceAll("-","");
    }

    function randomHex(len){
        return [...window.crypto.getRandomValues(new Uint8Array(len?parseInt(len):32))].map(m=>('0'+m.toString(16)).slice(-2)).join('');
    }

	function hasCurvePrefix(key){
     	return Object.keys(_CURVE_J2JS).find(c=>( (key.startsWith(c+"+") ||  (key.startsWith(CURVE_J2JS(c)+"+")) )));
    }

    function getMessageEncoding(message) {          
      let enc = new TextEncoder();
      return enc.encode(message);
    }
    /**
     * Format string in order to have each line with length equal to 64
     * @param pemString String to format
     * @returns Formatted string
     */
    function formatPEM(pemString) {
        const PEM_STRING_LENGTH = pemString.length, LINE_LENGTH = 64;
        const wrapNeeded = PEM_STRING_LENGTH > LINE_LENGTH;
        if (wrapNeeded) {
            let formattedString = "", wrapIndex = 0;
            for (let i = LINE_LENGTH; i < PEM_STRING_LENGTH; i += LINE_LENGTH) {
                formattedString += pemString.substring(wrapIndex, i) + "\r\n";
                wrapIndex = i;
            }
            formattedString += pemString.substring(wrapIndex, PEM_STRING_LENGTH);
            return formattedString;
        }
        else {
            return pemString;
        }
    }  

    function decodePEM(pem, tag = "[A-Z0-9 ]+") {
        const pattern = new RegExp(`-{5}BEGIN ${tag}-{5}([a-zA-Z0-9=+\\/\\n\\r]+)-{5}END ${tag}-{5}`, "g");
        const res = [];
        let matches = null;
        // eslint-disable-next-line no-cond-assign
        while (matches = pattern.exec(pem)) {
            const base64 = matches[1]
                .replace(/\r/g, "")
                .replace(/\n/g, "");
            res.push(pvtsutils.Convert.FromBase64(base64));
        }
        return res;
    }

    /* eslint-disable deprecation/deprecation */
    function toPEM(buffer, tag) {
        if(typeof buffer =="string" && buffer.startsWith(`-----BEGIN ${tag}-----`))
          	return buffer;
      
        return [
            `-----BEGIN ${tag}-----`,
            typeof buffer =="string"?formatPEM(buffer):formatPEM(pvtsutils.Convert.ToBase64(buffer)),
            `-----END ${tag}-----`,
            "",
        ].join("\n");
    }

    function fromPEM(pem) {
        const base64 = pem
            .replace(/-{5}(BEGIN|END) .*-{5}/gm, "")
            .replace(/\s/gm, "");
        return pvtsutils.Convert.FromBase64(base64);
    }

    function toBase64(key){
      //const exportedPublicKeyAsString = String.fromCharCode.apply(null, new Uint8Array(key));
      
      let uint8Array = new Uint8Array(key);
      let exportedPublicKeyAsString = '';
      for (let i = 0; i < uint8Array.length; i++) {
        exportedPublicKeyAsString += String.fromCharCode(uint8Array[i]);
      }
      
      const exportedPublicKeyAsBase64 = window.btoa(exportedPublicKeyAsString);
      return exportedPublicKeyAsBase64;
    }    
        
    // Function to convert a base64-encoded string to an ArrayBuffer
    function base64ToArrayBuffer(base64) {
      /*const binaryString = atob(base64);
      const arrayBuffer = new ArrayBuffer(binaryString.length);
      const uint8Array = new Uint8Array(arrayBuffer);

      for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
      }

      return arrayBuffer;*/
      return fromPEM(base64);
    }   
    
    async function shaHex(message,algo) {
      const msgUint8 = typeof message == "string"?new TextEncoder().encode(message):message; // encode as (utf-8) Uint8Array
      const hashBuffer = await crypto.subtle.digest(algo, msgUint8); // hash the message
      const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
      const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""); // convert bytes to hex string
      return hashHex;
    }

    async function sha1Hex(message) {
      return await shaHex(message,"SHA-1");
    }

    async function sha2Hex(message) {
      return await shaHex(message,"SHA-256");
    }

    async function hmacHex(text,hmacKey){
       return hmacUtil.hex(hmacUtil.sign(hmacKey,text));
    }

    /*
      Derive an AES key, given:
      - our ECDH private key
      - their ECDH public key
    */
    function deriveSecretKey(type,privateKey, publicKey) {
      return window.crypto.subtle.deriveKey(
        {
          name: type/*"ECDH"*/,
          public: publicKey,
        },
        privateKey,
        {
          name: "AES-GCM",
          length: 256,
        },
        false,
        ["encrypt", "decrypt"],
      );
    }

	/*
    Derive a shared secret, given:
    - our ECDH private key
    - their ECDH public key
    */
    async function deriveSharedSecret(name,privateKey, publicKey,curve) {
                
        const secret = await window.crypto.subtle.deriveBits(
          (curve?{
            name: name, 
            namedCurve:CURVE_J2JS(curve),
            public: publicKey 
          }:{ 
            name: name, 
            public: publicKey 
          }),
          privateKey,
          AES_KEY_SIZE*2
        );

        /*return window.crypto.subtle.importKey(
          "raw",
          secret,
          { name: "HKDF" },
          true,
          ["deriveKey"]
        );*/
        return secret;
    }

	async function getAESKey(secret){
        let AESKeyMaterial = await crypto.subtle.digest("SHA-256", secret); // hash the message
      	AESKeyMaterial = new Uint8Array(AESKeyMaterial.slice(0, AES_KEY_SIZE/BYTE_SIZE));
        return AESKeyMaterial;
    }

    async function aliceKeyGen(curve,cb) {
      
      // Generate 2 key pairs: one for Alice and one for Bob
      // In more normal usage, they would generate their key pairs
      // separately and exchange public keys securely
      let alicesKeyPair = await window.crypto.subtle.generateKey(
        (curve?{
          name:"ECDH",
          namedCurve: CURVE_J2JS(curve),//"P-384"
        }:{name: "DH"}),
        true,
        ["deriveBits","deriveKey"],
      );

      let privateKey =  await crypto.subtle.exportKey("pkcs8",alicesKeyPair.privateKey);
      let publicKey = await crypto.subtle.exportKey("spki",alicesKeyPair.publicKey);
      
      //send publicKey to Bob
      return {
        bobsResponse:async function(bobsPublicKey){
           let alicesExportedKeyPair = {"publicKey":curve+"+"+toPEM(publicKey,"PUBLIC KEY"),"privateKey":/*alicesKeyPair.privateKey*/toPEM(privateKey,"PRIVATE KEY")};
           return await bobsResponseKeyGen(bobsPublicKey,/*alicesKeyPair*/alicesExportedKeyPair,curve,cb);
        },
        publicKey:alicesKeyPair.publicKey,
        publicKeyBase64:curve+"+"+toPEM(publicKey,"PUBLIC KEY"),
        privateKey:alicesKeyPair.privateKey,
        privateKeyBase64:toPEM(privateKey,"PRIVATE KEY")
      }
    }

    async function bobKeyGen(alicesPublicKey,curve) {
	  let _alicesPublicKey = alicesPublicKey;
      let _curve = curve;
      
      if(typeof _alicesPublicKey == "string"){
            
            if(typeof _curve == "undefined" || _curve == null){
                if(hasCurvePrefix(_alicesPublicKey)){
                    _curve = _alicesPublicKey.substring(0,_alicesPublicKey.indexOf("+"));
                    _alicesPublicKey = _alicesPublicKey.substring(_alicesPublicKey.indexOf("+")+1);
                }
            }
        
			if(typeof _curve == "undefined" || _curve == null){
                console.log("Unable to complete bob keypair gen for ECDH Key exchange, no curve specified.");
                return;
            }
        
           if(hasCurvePrefix(_alicesPublicKey))
                  _alicesPublicKey = _alicesPublicKey.substring(_alicesPublicKey.indexOf("+")+1);
        //console.log("bobKeyGen1")
          _alicesPublicKey = await window.crypto.subtle.importKey(
              "spki", // Key format (could be "raw", "spki", or "pkcs8" based on the key type)
              base64ToArrayBuffer(_alicesPublicKey),
              (_curve?{
                name:"ECDH",
                namedCurve: CURVE_J2JS(_curve),//"P-384"
              }:{name: "DH"}), 
              true, 
              [/*"deriveBits"*/] // Specify the key usages as needed
            );
       }      
      //console.log("bobKeyGen2")
      let bobsKeyPair = await window.crypto.subtle.generateKey(
        (_curve?{
          name:"ECDH",
          namedCurve: CURVE_J2JS(_curve),//"P-384"
        }:{name: "DH"}),
        true,
        ["deriveBits","deriveKey"]
      );
//console.log("bobKeyGen3")
      let privateKey =  await crypto.subtle.exportKey("pkcs8",bobsKeyPair.privateKey);
      let publicKey = await crypto.subtle.exportKey("spki",bobsKeyPair.publicKey);

      // Bob generates the same secret key using his private key and Alice's public key.
      let bobsSecretKey = await deriveSharedSecret(
        _curve?"ECDH":"DH",
        bobsKeyPair.privateKey,
        _alicesPublicKey/*bobsKeyPair.publicKey*/,
        _curve
      );
      
      //send Bob's public key back to Alice
      //await alicesKeyRequest.deriveSecret(bobsKeyPair.publicKey);
      
      let AESKey =  await getAESKey(bobsSecretKey);
      
      return {
       	"publicKeyBase64":_curve+"+"+toPEM(publicKey,"PUBLIC KEY"),
        "publicKey":bobsKeyPair.publicKey,
        "privateKeyBase64":toPEM(privateKey,"PRIVATE KEY"),
        "privateKey":bobsKeyPair.privateKey,
        "sharedSecret":toBase64(bobsSecretKey),
        "AESKey":toBase64(AESKey),
        "keySize":AES_KEY_SIZE
      }
    }

	async function bobsResponseKeyGen(bobsPublicKey,alicesKeyPair,curve,cb){
                let _bobsPublicKey = bobsPublicKey;
      			let _alicesPrivateKey = alicesKeyPair.privateKey;
                let _alicesPublicKey = alicesKeyPair.publicKey;
      //console.log("bobsResponseKeyGen")
      			let _curve = curve;
      			if(typeof _curve == "undefined" || _curve == null){
                    if(hasCurvePrefix(_bobsPublicKey)){
                       _curve = _bobsPublicKey.substring(0,_bobsPublicKey.indexOf("+"));
                       _bobsPublicKey = _bobsPublicKey.substring(_bobsPublicKey.indexOf("+")+1);
                    }
                }
      
      			if(typeof _curve == "undefined" || _curve == null){
                    if(hasCurvePrefix(_alicesPublicKey)){
                       _curve = _alicesPublicKey.substring(0,_alicesPublicKey.indexOf("+"));
                       _alicesPublicKey = _alicesPublicKey.substring(_alicesPublicKey.indexOf("+")+1);
                    }
                }
      
      			if(typeof _curve == "undefined" || _curve == null){
                 	console.log("Unable to complete bob shared secret gen for ECDH Key exchange, no curve specified.");
                  	return;
                }
      
              if(typeof _bobsPublicKey == "string"){
                  if(hasCurvePrefix(_bobsPublicKey))
                    	_bobsPublicKey = _bobsPublicKey.substring(_bobsPublicKey.indexOf("+")+1);                   
                
                  _bobsPublicKey = await window.crypto.subtle.importKey(
                      "spki", 
                      base64ToArrayBuffer(_bobsPublicKey),
                      (_curve?{
                        name:"ECDH",
                        namedCurve: CURVE_J2JS(_curve),//"P-384"
                      }:{name: "DH"}), 
                      true, 
                      [/*"deriveBits"*/] // Specify the key usages as needed
                    );
                    //console.log("chrome debug1")
              }
      
      
              if(typeof _alicesPublicKey == "string"){
                  if(hasCurvePrefix(_alicesPublicKey))
                    	_alicesPublicKey = _alicesPublicKey.substring(_alicesPublicKey.indexOf("+")+1);                
                                  
                  _alicesPublicKey = await window.crypto.subtle.importKey(
                      "spki", 
                      base64ToArrayBuffer(_alicesPublicKey),
                      (_curve?{
                        name:"ECDH",
                        namedCurve: CURVE_J2JS(_curve),//"P-384"
                      }:{name: "DH"}), 
                      true, 
                      [/*"deriveBits"*/] // Specify the key usages as needed
                    );
                   //console.log("chrome debug2")
              }      
      
              if(typeof _alicesPrivateKey == "string"){                
                  _alicesPrivateKey = await window.crypto.subtle.importKey(
                      "pkcs8", 
                      base64ToArrayBuffer(_alicesPrivateKey),
                      (_curve?{
                        name:"ECDH",
                        namedCurve: CURVE_J2JS(_curve),//"P-384"
                      }:{name: "DH"}), 
                      true, 
                      ["deriveBits","deriveKey"] // Specify the key usages as needed
                    );                
                	//console.log(_alicesPublicKey,_alicesPrivateKey)
                    //console.log("chrome debug3")
              }
      
               //console.log(_alicesPrivateKey,_bobsPublicKey)
              // Alice then generates a secret key using her private key and Bob's public key.
              let alicesSecretKey = await deriveSharedSecret(
                _curve?"ECDH":"DH",
                _alicesPrivateKey,
                _bobsPublicKey,
                _curve
              );
      
      		  let AESKey = await getAESKey(alicesSecretKey);
      
              _alicesPublicKey = await crypto.subtle.exportKey("spki",_alicesPublicKey);

              if(cb){
                   cb({
                      "publicKey":_curve+"+"+toPEM(_alicesPublicKey,"PUBLIC KEY"),
                      "sharedSecret":toBase64(alicesSecretKey),
                      "AESKey":toBase64(AESKey),
                      "keySize":AES_KEY_SIZE});
              }
          
          	  return {
                  "publicKey":_curve+"+"+toPEM(_alicesPublicKey,"PUBLIC KEY"),
                  "sharedSecret":toBase64(alicesSecretKey),
                  "AESKey":toBase64(AESKey),
                  "keySize":AES_KEY_SIZE
              }; 
    }

    /*
    Given some key material and some random salt,
    derive an AES key using HKDF.
    */
    function HKDF(keyMaterial, salt,algo) {
      let _salt = salt?salt: window.crypto.getRandomValues(new Uint8Array(HMAC_LENGTH));
      
      return window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          salt: _salt,
          info: new Uint8Array("Encryption example"),
          hash: "SHA-256",
        },
        keyMaterial,
        {
          name: algo?algo:"AES-GCM",
          length: AES_KEY_SIZE 
        },
        true,
        ["encrypt", "decrypt"]);
    }

    async function encrypt(secret, plainText,algo,kdfType) {
        let _algo 		= algo?algo:"AES-GCM";
        let salt 		= window.crypto.getRandomValues(new Uint8Array(16));
      
        let key = secret;
      
        if(kdfType && kdfType == "HKDF"){
          
            if(typeof secret == "string"){
               key = await window.crypto.subtle.importKey(
                  "raw",
                  base64ToArrayBuffer(secret),
                  { name: "HKDF" },
                  true,
                  ["deriveKey"]);
            }
          	key = await HKDF(key, salt,_algo);
        }
      	else
        if(/*kdfType && kdfType == "SHA2_128_KDF"*/  _algo != "RSA-OAEP"){
              if(typeof secret == "string"){
                key = await window.crypto.subtle.importKey(
                  "raw",
                  base64ToArrayBuffer(key),
                  { 
                    name: algo 
                  }, 
                  true, 
                  ["encrypt"]
                );
            }
        }
      
        let ciphertext;      
        if(_algo == "AES-GCM")
          	ciphertext = await AES_GCM_CIPHER.encryptMessage(key,plainText);
      	else
		if(_algo == "AES-CBC")
          	ciphertext = await AES_CBC_CIPHER.encryptMessage(key,plainText);
      	else
		if(_algo == "AES-CTR")
          	ciphertext = await AES_CTR_CIPHER.encryptMessage(key,plainText);
        else
        if(_algo == "RSA-OAEP")
            ciphertext = await RSA_OAEP_CIPHER.encryptMessage(key,plainText);

        ciphertext = new Uint8Array([...salt, ...new Uint8Array(base64ToArrayBuffer(ciphertext))]);
        return toBase64(ciphertext);
    }

    async function decrypt(secret,ciphertext,algo,kdfType) {
        let _algo 		= algo?algo:"AES-GCM";
        let ctBuffer 	= base64ToArrayBuffer(ciphertext);
        let salt	 	= new Uint8Array(ctBuffer.slice(0,16));
      
             
        let key = secret;
      
        if(kdfType && kdfType == "HKDF"){
          
            if(typeof secret == "string"){
               key = await window.crypto.subtle.importKey(
                  "raw",
                  base64ToArrayBuffer(secret),
                  { name: "HKDF" },
                  true,
                  ["deriveKey"]);
            }
          	key = await HKDF(key, salt,_algo);
        }
      	else
        if(/*kdfType && kdfType == "SHA2_128_KDF" &&*/ _algo != "RSA-OAEP"){
              if(typeof secret == "string"){
                key = await window.crypto.subtle.importKey(
                  "raw",
                  base64ToArrayBuffer(key),
                  { 
                    name: algo 
                  }, 
                  true, 
                  ["decrypt"]
                );
            }
        }
      
      	let plaintext;
        if(_algo == "AES-GCM")
          	plaintext = await AES_GCM_CIPHER.decryptMessage(key,new Uint8Array(ctBuffer.slice(16)));
      	else
		if(_algo == "AES-CBC")
          	plaintext = await AES_CBC_CIPHER.decryptMessage(key,new Uint8Array(ctBuffer.slice(16)));
      	else
		if(_algo == "AES-CTR")
          	plaintext = await AES_CTR_CIPHER.decryptMessage(key,new Uint8Array(ctBuffer.slice(16)));
		else
        if(_algo == "RSA-OAEP")
            plaintext = await RSA_OAEP_CIPHER.decryptMessage(key,new Uint8Array(ctBuffer.slice(16)));
      
        return  plaintext;
    }

    const RSA_OAEP_CIPHER = {        

        /*
        Get the encoded message, encrypt it and display a representation
        of the ciphertext in the "Ciphertext" element.
        */
        encryptMessage:async function (key,message) {
          let encoded = getMessageEncoding(message);
          
		  let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "spki",
                base64ToArrayBuffer(_key),
                { 
                  name: "RSA-OAEP",
                  hash: "SHA-256" 
                }, 
                true, 
                ["encrypt"]
              );
          }
          
          let ciphertext = await window.crypto.subtle.encrypt(
            {
              name: "RSA-OAEP"
            },
            _key,
            encoded
          );
          return toBase64(ciphertext);
        },

        /*
        Fetch the ciphertext and decrypt it.
        Write the decrypted message into the "Decrypted" box.
        */
        decryptMessage:async function (key,ciphertext) {
          let ctBuffer = typeof ciphertext == "string"?base64ToArrayBuffer(ciphertext):ciphertext;
          
		  let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "pkcs8",
                base64ToArrayBuffer(_key),
                { 
                  name: "RSA-OAEP",
                  hash: "SHA-256" 
                }, 
                true, 
                ["decrypt"]
              );
          }     
          
          let decrypted = await window.crypto.subtle.decrypt(
            {
              name: "RSA-OAEP"
            },
            _key,
            ctBuffer
          );

          let dec = new TextDecoder();
          return dec.decode(decrypted);
        },

        /*
        Generate an encryption key pair, then set up event listeners
        on the "Encrypt" and "Decrypt" buttons.
        */
 		generateKeyPair: async function(){
              let keyPair = await window.crypto.subtle.generateKey(
                {
                name: "RSA-OAEP",
                // Consider using a 4096-bit key for systems that require long-term security
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
                },
                true,
                ["encrypt", "decrypt"]
              );

              let privateKey =  await crypto.subtle.exportKey("pkcs8",keyPair.privateKey);
              let publicKey = await crypto.subtle.exportKey("spki",keyPair.publicKey);

          	  let kp = {
                "privateKey":/*toBase64*/(toPEM(privateKey,"PRIVATE KEY")),
                "publicKey":/*toBase64*/(toPEM(publicKey,"PUBLIC KEY"))
              };
              kp.publicKeySig = await sha2Hex(kp.publicKey);
              kp.privateKeySig = await sha2Hex(kp.privateKey);
          	  return kp;
        }
    };

	const AES_CTR_CIPHER = {

        /*
        Get the encoded message, encrypt it and display a representation
        of the ciphertext in the "Ciphertext" element.
        */
        encryptMessage:async function (key,message) {
          let encoded = getMessageEncoding(message);
          // The counter block value must never be reused with a given key.
          let counter = window.crypto.getRandomValues(new Uint8Array(16));
          
          let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "raw",
                base64ToArrayBuffer(_key),
                { 
                  name: "AES-CTR" 
                }, 
                true, 
                ["encrypt"]
              );
          }
          
          let ciphertext = await window.crypto.subtle.encrypt(
            {
              name: "AES-CTR",
              counter:counter,
              length: 64
            },
            _key,
            encoded
          );

          ciphertext = new Uint8Array([ ...counter, ...new Uint8Array(ciphertext)]);
          return toBase64(ciphertext);
        },

        /*
        Fetch the ciphertext and decrypt it.
        Write the decrypted message into the "Decrypted" box.
        */
        decryptMessage:async function (key,ciphertext) {
          let ctBuffer = typeof ciphertext == "string"?base64ToArrayBuffer(ciphertext):ciphertext;
          
          let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "raw",
                base64ToArrayBuffer(_key),
                { 
                  name: "AES-CTR" 
                }, 
                true, 
                ["decrypt"]
              );
          }
          
          let decrypted = await window.crypto.subtle.decrypt(
            {
              name: "AES-CTR",
              counter:new Uint8Array(ctBuffer.slice(0, 16)),
              length: 64
            },
            _key,
            new Uint8Array(ctBuffer.slice(16))
          );

          let dec = new TextDecoder();
          return dec.decode(decrypted);
        },

        /*
        Generate an encryption key, then set up event listeners
        on the "Encrypt" and "Decrypt" buttons.
        */
		generateKey: async function(){
            let key = await window.crypto.subtle.generateKey(
              {
                  name: "AES-CTR",
                  length: AES_KEY_SIZE
              },
              true,
              ["encrypt", "decrypt"]
            );
            key =  await crypto.subtle.exportKey("raw",key);
          	return toBase64(key);
        }
    }

    const AES_CBC_CIPHER = {
        /*
        Get the encoded message, encrypt it and display a representation
        of the ciphertext in the "Ciphertext" element.
        */
        encryptMessage:async function (key,message) {
          let encoded = getMessageEncoding(message);
          // The iv must never be reused with a given key.
          let iv = window.crypto.getRandomValues(new Uint8Array(16));
          
          let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "raw",
                base64ToArrayBuffer(_key),
                { 
                  name: "AES-CBC" 
                }, 
                true, 
                ["encrypt"]
              );
          }
          
          let ciphertext = await window.crypto.subtle.encrypt(
            {
              name: "AES-CBC",
              iv
            },
            _key,
            encoded
          );

          ciphertext = new Uint8Array([ ...iv, ...new Uint8Array(ciphertext)]);
          return toBase64(ciphertext);
        },

        /*
        Fetch the ciphertext and decrypt it.
        Write the decrypted message into the "Decrypted" box.
        */
        decryptMessage:async function (key,ciphertext) {
          let ctBuffer = typeof ciphertext == "string"?base64ToArrayBuffer(ciphertext):ciphertext;
          
          let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "raw",
                base64ToArrayBuffer(_key),
                { 
                  name: "AES-CBC" 
                }, 
                true, 
                ["decrypt"]
              );
          }
          
          let decrypted = await window.crypto.subtle.decrypt(
            {
              name: "AES-CBC",
              iv:new Uint8Array(ctBuffer.slice(0, 16))
            },
            _key,
            new Uint8Array(ctBuffer.slice(16))
          );
          return  new TextDecoder().decode(decrypted);
        },

        /*
        Generate an encryption key, then set up event listeners
        on the "Encrypt" and "Decrypt" buttons.
        */
		generateKey: async function(){
            let key = await window.crypto.subtle.generateKey(
              {
                  name: "AES-CBC",
                  length: AES_KEY_SIZE
              },
              true,
              ["encrypt", "decrypt"]
            );
          
            key =  await crypto.subtle.exportKey("raw",key);
          	return toBase64(key);
        }
    }
    
    const AES_GCM_CIPHER = {
        /*
        Get the encoded message, encrypt it and display a representation
        of the ciphertext in the "Ciphertext" element.
        */
        encryptMessage:async function (key,message) {
          let encoded = getMessageEncoding(message);
          // The iv must never be reused with a given key.
          let iv = window.crypto.getRandomValues(new Uint8Array(GCM_NONCE_LENGTH));
          
          let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "raw",
                base64ToArrayBuffer(_key),
                { 
                  name: "AES-GCM" 
                }, 
                true, 
                ["encrypt"]
              );
          }
          
          let ciphertext = await window.crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: iv
            },
            _key,
            encoded
          );
		  ciphertext = new Uint8Array([ ...iv, ...new Uint8Array(ciphertext)]);
          return toBase64(ciphertext);
        },

        /*
        Fetch the ciphertext and decrypt it.
        Write the decrypted message into the "Decrypted" box.
        */
        decryptMessage:async function (key,ciphertext) {
          let ctBuffer = typeof ciphertext == "string"?base64ToArrayBuffer(ciphertext):ciphertext;
          
          let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "raw",
                base64ToArrayBuffer(_key),
                { 
                  name: "AES-GCM" 
                }, 
                true, 
                ["decrypt"]
              );
          }
          
          let decrypted = await window.crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: new Uint8Array(ctBuffer.slice(0, GCM_NONCE_LENGTH))
            },
            _key,
            new Uint8Array(ctBuffer.slice(GCM_NONCE_LENGTH))
          );

          let dec = new TextDecoder();
          return dec.decode(decrypted);
        },

        /*
        Generate an encryption key, then set up event listeners
        on the "Encrypt" and "Decrypt" buttons.
        */
		generateKey: async function(){
            let key = await window.crypto.subtle.generateKey(
              {
                  name: "AES-GCM",
                  length: AES_KEY_SIZE,
              },
              true,
              ["encrypt", "decrypt"]
            );
          
            key =  await crypto.subtle.exportKey("raw",key);
			return toBase64(key);
        }
    }
    
    const ECDSA_SIGNER = {
        signMessage:async function (key,message){
          let _key = key;
           
          let curvePrefix = "P-384";
          if(typeof _key == "string"){            
            if(hasCurvePrefix(_key)){
               curvePrefix = _key.substring(0,_key.indexOf("+"));
               _key = _key.substring(_key.indexOf("+")+1);
            }
            
            _key = await window.crypto.subtle.importKey(
                "pkcs8", 
                base64ToArrayBuffer(_key),
                (curvePrefix?{
                  name:"ECDSA",
                  namedCurve: CURVE_J2JS(curvePrefix),
                }:{name: "DSA"}), 
                true, 
                ["sign"]);
          }
          
          let signature = await window.crypto.subtle.sign(
            {
              name: curvePrefix?"ECDSA":"DSA",
              hash: { name: "SHA-256" },
            },
            _key,
            getMessageEncoding(message)); 
          return toBase64(signature);
        },
        verifyMessage:async function(key,message,signature){
              let sigBuffer = base64ToArrayBuffer(signature);
              let encoded = getMessageEncoding(message);
          
          	  let curvePrefix = "P-384";
              let _key = key;
              if(typeof _key == "string"){                
                if(hasCurvePrefix(_key)){
                   curvePrefix = _key.substring(0,_key.indexOf("+"));
                   _key = _key.substring(_key.indexOf("+")+1);
                }
                
                _key = await window.crypto.subtle.importKey(
                    "spki", // Key format (could be "raw", "spki", or "pkcs8" based on the key type)
                    base64ToArrayBuffer(_key),
                    (curvePrefix?{
                      name:"ECDSA",
                      namedCurve: CURVE_J2JS(curvePrefix),
                    }:{name: "DSA"}), 
                    true, 
                    ["verify"]);
              }
          
              let result = await window.crypto.subtle.verify(
                {
                  name: curvePrefix?"ECDSA":"DSA",
                  hash: { name: "SHA-256" },
                },
                _key,
                sigBuffer,
                encoded);
          	  return result;
        },
        generateKeyPair:async function (algo,curve="secp384r1"/*appears web crypto doesn't support P-256 for this??*/){
              let _curve = curve && curve.length>0?curve:"P-384";
          
              let keyPair = await window.crypto.subtle.generateKey(
              (_curve?{
                  name:"ECDSA",
                  namedCurve: CURVE_J2JS(_curve),
                }:{name: "DSA"}),
              true,
              ["sign","verify"]);

              let privateKey =  await crypto.subtle.exportKey("pkcs8",keyPair.privateKey);
              let publicKey = await crypto.subtle.exportKey("spki",keyPair.publicKey);
              
              const privateKeyStr = /*toBase64*/(toPEM(privateKey,"PRIVATE KEY"));//`-----BEGIN PRIVATE KEY-----\n${exportedPrivateKeyAsBase64}\n-----END PRIVATE KEY-----`;             
              const publicKeyStr = /*toBase64*/(toPEM(publicKey,"PUBLIC KEY"));//`-----BEGIN PUBLIC KEY-----\n${exportedPublicKeyAsBase64}\n-----END PUBLIC KEY-----`;

              let kp = {
                "privateKey":CURVE_J2JS(_curve)+"+"+privateKeyStr,
                "publicKey":CURVE_J2JS(_curve)+"+"+publicKeyStr
              };
              kp.publicKeySig = await sha2Hex(kp.publicKey);
              kp.privateKeySig = await sha2Hex(kp.privateKey);
              return kp;
        }      
    }   
    
    /*const DSA_SIGNER = {
        signMessage:async function (key,message){
          let signature = await window.crypto.subtle.sign(
            {
              name: "DSA",
              hash: { name: "SHA-384" },
            },
            key,
            getMessageEncoding(message),
          ); 
          return toBase64(signature);
        },
        verifyMessage:async function(key,signature){
            
              let encoded = getMessageEncoding(signature);
              let result = await window.crypto.subtle.verify(
                {
                  name: "DSA",
                  hash: { name: "SHA-384" },
                },
                key,
                signature,
                encoded,
              );
          	  return result;
        }
    }*/
    const RSA_SIGNER = {
        signMessage:async function (key,message,pss){
                    
          let _key  = key;
          if(typeof _key == "string"){            
              _key = await window.crypto.subtle.importKey(
                "pkcs8",
                base64ToArrayBuffer(_key),
                (pss?{
                  name: "RSA-PSS",
                  saltLength:32,
                  hash: "SHA-256"
                }:{
                  name: "RSASSA-PKCS1-v1_5",
                  hash: "SHA-256" 
                }), 
                true, 
                ["sign"]
              );
          }
          
          let signature = await window.crypto.subtle.sign(
            (pss?{
              name:"RSA-PSS",
              hash: { name: "SHA-256" },
              saltLength:32
            }:{
              name:"RSASSA-PKCS1-v1_5",
              hash: { name: "SHA-256" }
            }),
            _key,
            getMessageEncoding(message)); 
          return toBase64(signature);
        },
        verifyMessage:async function(key,message,signature,pss){
              let sigBuffer = base64ToArrayBuffer(signature);
              let encoded = getMessageEncoding(message);          
          
              let _key  = key;
              if(typeof _key == "string"){
                  _key = await window.crypto.subtle.importKey(
                      "spki",
                      base64ToArrayBuffer(_key),
                      (pss?{
                        name: "RSA-PSS",
                        saltLength:32,
                        hash: "SHA-256"
                      }:{
                        name: "RSASSA-PKCS1-v1_5",
                        hash: "SHA-256" 
                      }), 
                      true, 
                      ["verify"]
                  );
              }
          
              let result = await window.crypto.subtle.verify(
                (pss?{
                  name:"RSA-PSS",
                  hash: { name: "SHA-256" },
                  saltLength:32
                }:{
                  name:"RSASSA-PKCS1-v1_5",
                  hash: { name: "SHA-256" }
                }),
                _key,
                sigBuffer,
                encoded);
          	  return result;
        },
        generateKeyPair:async function (pss){
              let keyPair = await window.crypto.subtle.generateKey(
              {
                name: (pss?"RSA-PSS":"RSASSA-PKCS1-v1_5"),
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
              },
              true,
              ["sign","verify"]);

              let privateKey =  await crypto.subtle.exportKey("pkcs8",keyPair.privateKey);
              let publicKey = await crypto.subtle.exportKey("spki",keyPair.publicKey);

              const privateKeyStr = /*toBase64*/(toPEM(privateKey,"PRIVATE KEY"));//`-----BEGIN PRIVATE KEY-----\n${exportedPrivateKeyAsBase64}\n-----END PRIVATE KEY-----`;             
              const publicKeyStr = /*toBase64*/(toPEM(publicKey,"PUBLIC KEY"));//`-----BEGIN PUBLIC KEY-----\n${exportedPublicKeyAsBase64}\n-----END PUBLIC KEY-----`;

              let kp = {
                "privateKey":privateKeyStr,
                "publicKey":publicKeyStr
              };
              kp.publicKeySig = await sha2Hex(kp.publicKey);
              kp.privateKeySig = await sha2Hex(kp.privateKey);
              return kp;
        }
    }

	export {
      	bobKeyGen,
      	aliceKeyGen,
        bobsResponseKeyGen,
      	setDHParams,
        getDHParams,
        RSA_OAEP_CIPHER,
        AES_CTR_CIPHER,
        AES_CBC_CIPHER,
        AES_GCM_CIPHER,
      	ECDSA_SIGNER,
        //DSA_SIGNER,
        RSA_SIGNER,
      	encrypt,
        decrypt,
        shaHex,
        hmacHex,
        randomUUID,
        randomHex
	}
