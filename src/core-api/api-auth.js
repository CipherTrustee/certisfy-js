import * as helperUtil from '../utils/helpers.js';

const {isValidString} = helperUtil;

////////////////////////////////////////////////Crypto support///////////////////////////////////////////////
//Ported from Java by Chatgpt.
function getSigningAlgo(signingAlgo, defaultAlgo) {
    if (signingAlgo && signingAlgo.length > 0) {
      const algo = signingAlgo.toUpperCase();

      if (algo === "RSA")
        return "SHA256withRSA";
      else if (algo === "RSA-PSS")
        return "SHA256withRSA/PSS";
      else if (algo === "ECDSA")
        return "SHA256withPLAIN-ECDSA";
      else
        return signingAlgo;
    }
    return defaultAlgo;
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

function normalizeKey(base64OrPem) {
  // remove PEM headers if present
  if (base64OrPem.includes("BEGIN")) {
    return base64OrPem
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .replace(/\s+/g, "");
  }
  return base64OrPem;
}

async function importPrivateKey(base64Key, algoName) {
    const keyBuffer = base64ToArrayBuffer(base64Key);

    let algorithm;

    if (algoName === "SHA256withRSA") {
      algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      };
    } 
    else if (algoName === "SHA256withRSA/PSS") {
      algorithm = {
        name: "RSA-PSS",
        hash: "SHA-256"
      };
    } 
    else if (algoName === "SHA256withPLAIN-ECDSA") {
      algorithm = {
        name: "ECDSA",
        namedCurve: "P-256"
      };
    }

    return crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      algorithm,
      false,
      ["sign"]
    );
}

async function signData(data, base64PrivateKey, signingAlgo, defaultAlgo) {
    const algo = getSigningAlgo(signingAlgo, defaultAlgo);

    // convert string → Uint8Array
    if (typeof data === "string") {
      data = new TextEncoder().encode(data);
    }

    const privateKey = await importPrivateKey(normalizeKey(base64PrivateKey), algo);

    let cryptoAlgo;

    if (algo === "SHA256withRSA") {
      cryptoAlgo = {
        name: "RSASSA-PKCS1-v1_5"
      };
    } 
    else if (algo === "SHA256withRSA/PSS") {
      cryptoAlgo = {
        name: "RSA-PSS",
        saltLength: 32
      };
    } 
    else if (algo === "SHA256withPLAIN-ECDSA") {
      cryptoAlgo = {
        name: "ECDSA",
        hash: "SHA-256"
      };
    }

    const signature = await crypto.subtle.sign(
      cryptoAlgo,
      privateKey,
      data
    );

    return signature;
}

function encodeBase64String(signatureBuffer) {
    const bytes = new Uint8Array(signatureBuffer);
    let binary = "";

    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
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
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

async function generateBearerToken(signingInfo,stringToSign){
	let authorization;
  	if(signingInfo.signRequest){
    	authorization = await signingInfo.signRequest(await sha2Hex(stringToSign),signData);
    }
    else
    {
    	let sig =   encodeBase64String(await signData(await sha2Hex(stringToSign),signingInfo.privateKeyBase64,signingInfo.algo));
      	authorization = `${signingInfo.signerID}:${sig}`;
    }
  	return authorization;
}

async function signRequest(args,apiTarget,signingInfo){
  	let action = args["pki_action"]?args["pki_action"]:args["action"];
  	if(!action)
      	action = args["trp_action"]
  
  
	if(action == "post-csr")
      	return postCSR(args,apiTarget,signingInfo)
  
	if(action == "get-csr")
      	return getCSR(args,apiTarget,signingInfo)  
  
	if(action == "delete-csr")
      	return deleteCSR(args,apiTarget,signingInfo)

  
	if(action == "post-cert")
      	return postCert(args,apiTarget,signingInfo)
  
	if(action == "get-cert")
      	return getCert(args,apiTarget,signingInfo)  
  
	if(action == "delete-cert")
      	return deleteCert(args,apiTarget,signingInfo)  
  
  
	if(action == "post-dh-exchange")
      	return postDHExchange(args,apiTarget,signingInfo)
  
	if(action == "get-dh-exchange")
      	return getDHExchange(args,apiTarget,signingInfo)  
  
	if(action == "delete-dh-exchange")
      	return deleteDHExchange(args,apiTarget,signingInfo)
    
  
	if(action == "post-cert-identity")
      	return postCertIdentity(args,apiTarget,signingInfo)  
  
	if(action == "get-cert-chain")
      	return getCertChain(args,apiTarget,signingInfo)  
  
  
	if(action == "post-signature")
      	return postSignature(args,apiTarget,signingInfo)
  
	if(action == "update-signature")
      	return updateSignature(args,apiTarget,signingInfo) 
  
	if(action == "get-signature")
      	return getSignature(args,apiTarget,signingInfo)  
  
	if(action == "delete-signature")
      	return deleteSignature(args,apiTarget,signingInfo)
  
  
	if(action == "post-verify")
      	return postVerify(args,apiTarget,signingInfo)
  
	if(action == "post-service-request")
      	return postServiceRequest(args,apiTarget,signingInfo)
}


async function postCSR(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/pki/csr\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";

    //lexicographically ordered request parameters
  
    //pki_sp_uri - optional
    if(args["pki_sp_uri"]){
      queryString += (ampersand+"pki_sp_uri="+args["pki_sp_uri"]);
      ampersand = "&";
    }
  
    //cert_download_key - optional
    if(args["cert_download_key"]){
      queryString += (ampersand+"cert_download_key="+args["cert_download_key"]);
      ampersand = "&";
    }    
  
    //id_anchor_cert_object - optional
    if(args["id_anchor_cert_object"]){
      queryString += (ampersand+"id_anchor_cert_object="+args["id_anchor_cert_object"]);
      ampersand = "&";
    }  
  
    //payload - optional
    if(args["payload"]){
  	  queryString += (ampersand+"payload="+args["payload"]);
      ampersand = "&";
    }  
  
    //payment_info - optional
  	if(args["payment_info"]){
  	  queryString += (ampersand+"payment_info="+args["payment_info"]);
      ampersand = "&";
  	}  
  
    //payment_method - optional
  	if(args["payment_method"]){
  	  queryString += (ampersand+"payment_method="+args["payment_method"]);
      ampersand = "&";
  	}
  
    //payment_method_cert_key - optional
  	if(args["payment_method_cert_key"]){
  	  queryString += (ampersand+"payment_method_cert_key="+args["payment_method_cert_key"]);
      ampersand = "&";
  	}  
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}  
  
    //private_data - optional
  	if(args["private_data"]){
  	  queryString += (ampersand+"private_data="+args["private_data"]);
      ampersand = "&";
  	}

    //signer_signature - optional
  	if(args["signer_signature"]){
      queryString += (ampersand+"signer_signature="+args["signer_signature"]);
      ampersand = "&";
  	}
  
    //use_strong_id_proofing - optional
  	if(args["use_strong_id_proofing"]){
  	  queryString += (ampersand+"use_strong_id_proofing="+args["use_strong_id_proofing"]);
      ampersand = "&";
  	}    
  
    //user_generated_keypair - optional
  	if(args["user_generated_keypair"]){
  	  queryString += (ampersand+"user_generated_keypair="+args["user_generated_keypair"]);
      ampersand = "&";
  	}  
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":apiTarget+"/dh-exchange"
    }
}

async function getCSR(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
  	let useAPITarget = args["csr_id"]?(apiTarget+"/pki/csr/"+args["csr_id"]):apiTarget+"/pki/csr";
  
    let stringToSign = "GET\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
    //csr_id - optional
    if(args["csr_id"]){
  	  queryString += (ampersand+"csr_id="+args["csr_id"]);
      ampersand = "&";
    }
  
    //encryption_key - optional
    if(args["encryption_key"]){
  	  queryString += (ampersand+"encryption_key="+args["encryption_key"]);
      ampersand = "&";
    }
  
  	//id_proofing_claim_receiver_id - optional
    if(args["id_proofing_claim_receiver_id"]){
  	  queryString += (ampersand+"id_proofing_claim_receiver_id="+args["id_proofing_claim_receiver_id"]);
      ampersand = "&";
    }
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}    
  
    //private_key_encryption_key - optional
    if(args["private_key_encryption_key"]){
  	  queryString += (ampersand+"private_key_encryption_key="+args["private_key_encryption_key"]);
      ampersand = "&";
    }  
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"GET",
      "url":useAPITarget
    }
}

async function deleteCSR(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
  	let useAPITarget = args["csr_id"]?(apiTarget+"/pki/csr/"+args["csr_id"]):apiTarget+"/pki/csr";
  
    let stringToSign = "POST\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
	//csr_id - optional
    if(args["csr_id"]){
  	  queryString += (ampersand+"csr_id="+args["csr_id"]);
      ampersand = "&";
    }
  
    //encryption_key - optional
    if(args["encryption_key"]){
  	  queryString += (ampersand+"encryption_key="+args["encryption_key"]);
      ampersand = "&";
    }
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}    
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":useAPITarget
    }
}


async function postCert(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/pki/cert\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";

    //lexicographically ordered request parameters
  
    //cert_text - optional
  	if(args["cert_text"]){
  	  queryString += (ampersand+"cert_text="+args["cert_text"]);
      ampersand = "&";
  	}   
  
    //charge - optional
  	if(args["charge"]){
  	  queryString += (ampersand+"charge="+args["charge"]);
      ampersand = "&";
  	}  
  
    //charge_card_stripe_token - optional
  	if(args["charge_card_stripe_token"]){
  	  queryString += (ampersand+"charge_card_stripe_token="+args["charge_card_stripe_token"]);
      ampersand = "&";
  	}    
  
    //csr_id - optional
  	if(args["csr_id"]){
  	  queryString += (ampersand+"csr_id="+args["csr_id"]);
      ampersand = "&";
  	}   
  
    //encryption_key - optional
    if(args["encryption_key"]){
  	  queryString += (ampersand+"encryption_key="+args["encryption_key"]);
      ampersand = "&";
    }  
  
    //expire_time - optional
  	if(args["expire_time"]){
  	  queryString += (ampersand+"expire_time="+args["expire_time"]);
      ampersand = "&";
  	}

    //identity_link_sig - optional
  	if(args["identity_link_sig"]){
  	  queryString += (ampersand+"identity_link_sig="+args["identity_link_sig"]);
      ampersand = "&";
  	}
  
    //is_charge_card - optional
  	if(isValidString(args["is_charge_card"])){
  	  queryString += (ampersand+"is_charge_card="+args["is_charge_card"]);
      ampersand = "&";
  	}
  
    //lateral_limit - optional
    if(args["lateral_limit"]){
      queryString += (ampersand+"lateral_limit="+args["lateral_limit"]);
      ampersand = "&";
    }
  
    //make_delegate - optional
    if(args["make_delegate"]){
      queryString += (ampersand+"make_delegate="+args["make_delegate"]);
      ampersand = "&";
    }
  
    //payment_stripe_token - optional
  	if(args["payment_stripe_token"]){
  	  queryString += (ampersand+"payment_stripe_token="+args["payment_stripe_token"]);
      ampersand = "&";
  	}    
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}    
  
    //signer_cert_fingerprint - optional
  	if(args["signer_cert_fingerprint"]){
  	  queryString += (ampersand+"signer_cert_fingerprint="+args["signer_cert_fingerprint"]);
      ampersand = "&";
  	}
  
    //signer_key - optional
  	if(args["signer_key"]){
      queryString += (ampersand+"signer_key="+args["signer_key"]);
      ampersand = "&";
  	}  

    //signer_signature - optional
  	if(args["signer_signature"]){
      queryString += (ampersand+"signer_signature="+args["signer_signature"]);
      ampersand = "&";
  	} 
  
    //unlisted_cert - optional
    if(isValidString(args["unlisted_cert"])){
      queryString += (ampersand+"unlisted_cert="+args["unlisted_cert"]);
      ampersand = "&";
    }
  
    //unlisted_trust_anchor - optional
    if(isValidString(args["unlisted_trust_anchor"])){
      queryString += (ampersand+"unlisted_trust_anchor="+args["unlisted_trust_anchor"]);
      ampersand = "&";
    }
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":apiTarget+"/dh-exchange"
    }
}

async function getCert(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
  	let useAPITarget = args["fingerprint"]?(apiTarget+"/pki/cert/"+args["fingerprint"]):apiTarget+"/pki/cert";
  
    let stringToSign = "GET\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
    //csr_id - optional
  	if(args["csr_id"]){
  	  queryString += (ampersand+"csr_id="+args["csr_id"]);
      ampersand = "&";
  	}
  
    //fingerprint - optional
    if(args["fingerprint"]){
      queryString += (ampersand+"fingerprint="+args["fingerprint"]);
      ampersand = "&";
    }   
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}    
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"GET",
      "url":useAPITarget
    }
}

async function deleteCert(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
  	let useAPITarget = args["fingerprint"]?(apiTarget+"/pki/cert/"+args["fingerprint"]):apiTarget+"/pki/cert";
  
    let stringToSign = "POST\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
    //fingerprint - optional
  	if(args["fingerprint"]){
  	  queryString += (ampersand+"fingerprint="+args["fingerprint"]);
      ampersand = "&";
  	}   
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	} 
  
    //private_key - optional
    if(args["private_key"]){
  	  queryString += (ampersand+"private_key="+args["private_key"]);
      ampersand = "&";
    }
  
    //signer_signature - optional
    if(args["signer_signature"]){
  	  queryString += (ampersand+"signer_signature="+args["signer_signature"]);
      ampersand = "&";
    }
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":useAPITarget
    }
}


async function postDHExchange(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/dh-exchange\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";

    //lexicographically ordered request parameters
  
    //alice_data - optional
    if(args["alice_data"]){
      queryString += (ampersand+"alice_data="+args["alice_data"]);
      ampersand = "&";
    }  
  
    //alice_public_key - optional
    if(args["alice_public_key"]){
      queryString += (ampersand+"alice_public_key="+args["alice_public_key"]);
      ampersand = "&";
    }
  
    //bob_data - optional
    if(args["bob_data"]){
      queryString += (ampersand+"bob_data="+args["bob_data"]);
      ampersand = "&";
    }  
  
    //bob_public_key - optional
    if(args["bob_public_key"]){
      queryString += (ampersand+"bob_public_key="+ args["bob_public_key"]);
      ampersand = "&";
    }  
  
    //trp_action - optional
  	if(args["trp_action"]){
  	  queryString += (ampersand+"trp_action="+args["trp_action"]);
      ampersand = "&";
  	}    
  
    //user_code - optional
    if(args["user_code"]){
  	  queryString += (ampersand+"user_code="+args["user_code"]);
      ampersand = "&";
    }  

 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":apiTarget+"/dh-exchange"
    }
}

async function getDHExchange(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
  	let useAPITarget = args["user_code"]?(apiTarget+"/dh-exchange/"+args["user_code"]):apiTarget+"/dh-exchange";
  
    let stringToSign = "GET\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
    //trp_action - optional
  	if(args["trp_action"]){
  	  queryString += (ampersand+"trp_action="+args["trp_action"]);
      ampersand = "&";
  	}    
  
    //user_code - optional
    if(args["user_code"]){
  	  queryString += (ampersand+"user_code="+args["user_code"]);
      ampersand = "&";
    }
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"GET",
      "url":useAPITarget
    }
}

async function deleteDHExchange(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
  	let useAPITarget = args["user_code"]?(apiTarget+"/dh-exchange/"+args["user_code"]):apiTarget+"/dh-exchange";
  
    let stringToSign = "POST\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
    //trp_action - optional
  	if(args["trp_action"]){
  	  queryString += (ampersand+"trp_action="+args["trp_action"]);
      ampersand = "&";
  	}    
  
    //user_code - optional
    if(args["user_code"]){
  	  queryString += (ampersand+"user_code="+args["user_code"]);
      ampersand = "&";
    }
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":useAPITarget
    }
}


async function getCertChain(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
  	let useAPITarget = (args["fingerprint"]?(apiTarget+"/pki/cert/"+args["fingerprint"]+"/chain"):(apiTarget+"/pki/cert/chain"))
    let stringToSign = "GET\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
	//chain_health_check - optional
    if(args["chain_health_check"]){
  	  queryString += (ampersand+"chain_health_check="+args["chain_health_check"]);
      ampersand = "&";
    }  
  
    //fingerprint - optional
  	if(args["fingerprint"]){
  	  queryString += (ampersand+"fingerprint="+args["fingerprint"]);
      ampersand = "&";
  	}  
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}  
  
    //trust_root - optional
    if(isValidString(args["trust_root"])){
      queryString += (ampersand+"trust_root="+args["trust_root"]);
      ampersand = "&";
    } 
  
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"GET",
      "url":useAPITarget
    }
}

async function postCertIdentity(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let useAPITarget = (args["fingerprint"]?(apiTarget+"/pki/cert/"+args["fingerprint"]+"/identity"):(apiTarget+"/pki/cert/identity"));
  
    let stringToSign = "POST\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters  
    //enclosed_sig - optional
    if(args["enclosed_sig"]){
      queryString += (ampersand+"enclosed_sig="+args["enclosed_sig"]);
      ampersand = "&";
    } 
  
    //fingerprint - optional
    if(args["fingerprint"]){
      queryString += (ampersand+"fingerprint="+args["fingerprint"]);
      ampersand = "&";
    } 
  
    //id_anchor_cert_sig - optional
    if(args["id_anchor_cert_sig"]){
      queryString += (ampersand+"id_anchor_cert_sig="+args["id_anchor_cert_sig"]);
      ampersand = "&";
    } 
  
    //identity_link_sig - optional
  	if(args["identity_link_sig"]){
  	  queryString += (ampersand+"identity_link_sig="+args["identity_link_sig"]);
      ampersand = "&";
  	}
  
    //include_trust_chain - optional
  	if(isValidString(args["include_trust_chain"])){
  	  queryString += (ampersand+"include_trust_chain="+args["include_trust_chain"]);
      ampersand = "&";
  	}  
  
    //is_private_persona - optional
  	if(isValidString(args["is_private_persona"])){
  	  queryString += (ampersand+"is_private_persona="+args["is_private_persona"]);
      ampersand = "&";
  	}    
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}    
  
    //sp_uri - optional
    if(args["sp_uri"]){
      queryString += (ampersand+"sp_uri="+args["sp_uri"]);
      ampersand = "&";
    } 
  
    //vouch_for_claim_identities - optional
    if(args["vouch_for_claim_identities"]){
      queryString += (ampersand+"vouch_for_claim_identities="+args["vouch_for_claim_identities"]);
      ampersand = "&";
    } 
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
  
    //************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":useAPITarget
    }
}


async function postSignature(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/pki/signature\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
	let curl = [];
  
    //lexicographically ordered request parameters  
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}

    //signer_signature - optional
  	if(args["signer_signature"]){
      queryString += (ampersand+"signer_signature="+ args["signer_signature"]);
      ampersand = "&";
  	}  
  
  
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string******************** 
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":(apiTarget+"/pki/signature")
    }
}

async function updateSignature(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/pki/signature\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
	let curl = [];
  
    //lexicographically ordered request parameters
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	} 
  
    //signer_signature - optional
    if(args["signer_signature"]){
  	  queryString += (ampersand+"signer_signature="+args["signer_signature"]);
      ampersand = "&";
    }
   
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":(apiTarget+"/pki/signature")
    }
}

async function getSignature(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let useAPITarget = (args["sig_id"]?(apiTarget+"/pki/signature/"+args["sig_id"]):(apiTarget+"/pki/signature"));
  
    let stringToSign = "GET\n";
    stringToSign += `${useAPITarget}\n`;

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
	let curl = [];
  
    //lexicographically ordered request parameters
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}    
  
    //sig_id - optional
  	if(args["sig_id"]){
  	  queryString += (ampersand+"sig_id="+args["sig_id"]);
      ampersand = "&";
  	}
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string******************** 
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":useAPITarget
    }
}

async function deleteSignature(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/pki/signature\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
	let curl = [];
  
    //lexicographically ordered request parameters
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	} 
  
    //signer_signature - optional
    if(args["signer_signature"]){
  	  queryString += (ampersand+"signer_signature="+args["signer_signature"]);
      ampersand = "&";
    }
   
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string******************** 
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":(apiTarget+"/pki/signature")
    }
}


async function postVerify(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/pki/verify\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";
  
    //lexicographically ordered request parameters
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (args+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}
  
    //signature_payload - optional
  	if(args["signature_payload"]){
  	  queryString += (ampersand+"signature_payload="+args["signature_payload"]);
      ampersand = "&";
  	}
  
    //sp_uri - optional
  	if(args["sp_uri"]){
  	  queryString += (ampersand+"sp_uri="+args["sp_uri"]);
      ampersand = "&";
  	}  
 
    if(queryString.length>0)
      stringToSign += ("?"+queryString);
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);  
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":apiTarget+"/pki/verify"
    }
}

async function postServiceRequest(args,apiTarget,signingInfo){
    //********************************Begin signature base string********************
    let stringToSign = "POST\n";
    stringToSign += (apiTarget+"/pki/service\n");

    let timestamp = new Date().getTime();
    let queryString = "";
    let ampersand = "";

    //lexicographically ordered request parameters
  
    //pki_action - optional
  	if(args["pki_action"]){
  	  queryString += (ampersand+"pki_action="+args["pki_action"]);
      ampersand = "&";
  	}  
  
    //service_action - optional
  	if(args["service_action"]){
  	  queryString += (ampersand+"service_action="+args["service_action"]);
      ampersand = "&";
  	}

    //signer_signature - optional
  	if(args["signer_signature"]){
      queryString += (ampersand+"signer_signature="+args["signer_signature"]);
      ampersand = "&";
  	}
  
  
    stringToSign += "\n"+timestamp;
    //console.info("stringToSign:"+stringToSign);
    //********************************End signature base string********************
  
    return {
      "timestamp":timestamp,
      "authorization":(await generateBearerToken(signingInfo,stringToSign)),
      "method":"POST",
      "url":apiTarget+"/service"
    }
}



export {
    signData,
    sha1Hex,
    sha2Hex,
    normalizeKey,
    importPrivateKey,
    encodeBase64String,
  
  	getSigningAlgo,
	signRequest,
  
    postCSR,
    getCSR,
    deleteCSR,
  
    postCert,
    getCert,
    deleteCert,
  
	postDHExchange,
  	getDHExchange,
    deleteDHExchange,
  
  	getCertChain,
  	postCertIdentity,
  
  	postSignature,
    updateSignature,
    deleteSignature,
  	getSignature,
  
  	postVerify,
    postServiceRequest,
  
    generateBearerToken
}