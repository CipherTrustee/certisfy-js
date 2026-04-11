	import {asn1js,pkijs} from './pkijs.js';
    import * as cryptoUtil from './crypto.js';

	const {fromPEM,toPEM,sha2Hex,sha1Hex} = cryptoUtil;

    function getCertIssuer(cert){
      
       if(!cert.issuer)
         	return null;
       //#region Parse and display information about "subject"
        const typemap = {
            "2.5.4.6": "C",
            "2.5.4.11": "OU",
            "2.5.4.10": "O",
            "2.5.4.3": "CN",
            "2.5.4.7": "L",
            "2.5.4.8": "ST",
            "2.5.4.12": "T",
            "2.5.4.42": "GN",
            "2.5.4.43": "I",
            "2.5.4.4": "SN",
            "1.2.840.113549.1.9.1": "E-mail"
        };  


        let issuerCN = null;
        for (let i = 0; i < cert.issuer.typesAndValues.length; i++) {
            let typeval = typemap[cert.issuer.typesAndValues[i].type];
            if (typeof typeval === "undefined")
                typeval = cert.issuer.typesAndValues[i].type;

            const subjval = cert.issuer.typesAndValues[i].value.valueBlock.value;

            if (typeval === "CN") {
                issuerCN = subjval;
            }
        }
      	return issuerCN;
    }

	async function getCertIssuerFingerPrint(cert){
        let decodedCert = decodeCertificate(cert.cert_text);     
        let issuerThumbprint = getCertIssuer(decodedCert)/*.substring(3)*/;
              
        //replace encrypted issuer finger print if necessary
        if(certPayloadHasField(cert.cert_text,"pki-is-private-issuer","true") && cert.issuer_finger_print)
          issuerThumbprint  = cert.issuer_finger_print;
      
        return issuerThumbprint;      
    }

	function issuerIsPrivate(cert){
		return (certPayloadHasField(cert.cert_text,"pki-is-private-issuer","true") && !cert.issuer_finger_print);
    }


	async function getCertDerivationSourceFingerPrint(cert){
              
        if(cert.derived_from_cert_finger_print && cert.derived_from_cert_finger_print.trim().length>0)
          return cert.derived_from_cert_finger_print;
      
        return getCertPayloadField(cert.cert_text,"pki-cert-is-derived-from");      
    }

	async function getCertDerivationSourceIssuerFingerPrint(cert){
              
        if(cert.derived_from_cert_issuer_finger_print && cert.derived_from_cert_issuer_finger_print.trim().length>0)
          return cert.derived_from_cert_issuer_finger_print;
      
        return getCertPayloadField(cert.cert_text,"pki-cert-is-derived-from-issuer");      
    }

	function derivationSourceIsPrivate(cert){
		return (certPayloadHasField(cert.cert_text,"pki-is-private-derived-from-cert","true") && !cert.derived_from_cert_finger_print);
    }

	function derivationSourceIssuerIsPrivate(cert){
		return (certPayloadHasField(cert.cert_text,"pki-is-private-derived-from-cert-issuer","true") && !cert.derived_from_cert_issuer_finger_print);
    }

    /*
	async function getCertIssuerFingerPrint(cert){
       let decodedCert = typeof cert == "string"?decodeCertificate(cert):cert;
       return getCertIssuer(decodedCert);
    }*/

    async function getCertFingerPrint(cert){
      	let decodedCert = typeof cert == "string"?decodeCertificate(cert):cert;
        return await sha1Hex(decodedCert.toSchema(true).toBER(false));
    }

    function decodeCertificate(pem){
       return typeof pem == "string"?pkijs.Certificate.fromBER(fromPEM(pem)):pem;
    }

    function pemEncodeCert(cert){
     	return toPEM(cert.toSchema(true).toBER(false),"CERTIFICATE"); 
    }

    async function exportCertificate(cert,data){
        let decodedCert = typeof cert == "string"?decodeCertificate(cert):cert;
        let fingerPrint = await getCertFingerPrint(decodedCert);
      
        return Object.assign({
           "id":fingerPrint,
           "finger_print":fingerPrint,
           "issuer":getCertIssuer(decodedCert),
           "payload":getCertificatePayload(decodedCert),
           "cert_text":pemEncodeCert(decodedCert),
           "create_date":decodedCert.notBefore.value.getTime(),
           "validfrom_date":decodedCert.notBefore.value.getTime(),
           "expiration_date":decodedCert.notAfter.value.getTime(),
        },(data?data:{}));
    }

	async function extractCertPublicKey(pem,signAlg){
     	let publicKey  = Object.assign(signAlg=="ECDSA"?{"kty":"EC","ext":true}:{"kty":"RSA","ext":true,"alg":"RS256"},decodeCertificate(pem).subjectPublicKeyInfo.parsedKey.toJSON());
        
        publicKey  = await crypto.subtle.importKey("jwk",publicKey,(signAlg=="ECDSA"?{
                  name:"ECDSA",
                  namedCurve: publicKey.crv,
                }:{
                  name: "RSASSA-PKCS1-v1_5",
                  hash: "SHA-256" 
         }),true,["verify"]);
        
		publicKey = await crypto.subtle.exportKey("spki",publicKey);
              
        return toPEM(publicKey,"PUBLIC KEY");
    }

    function getCertificatePayload(certObject){     
      let cert = typeof certObject == "string"?decodeCertificate(certObject):certObject;
      
      //extract payload
        for (let i = 0; i < cert.extensions.length; i++) {
          if(cert.extensions[i].extnID == "2.5.29.17"){

            let altNameBin = asn1js.fromBER(cert.extensions[i].extnValue.toBER(false)).result;              
            let altNames = pkijs.GeneralNames.fromBER(altNameBin.getValue());
            let altName = altNames.names[0].value;

            //let altName = altNameBin.valueBlock.value[0].valueBlock.value[0].valueBlock.value[0].valueBlock.value
            return JSON.parse(altName);
          }
        }      
      /*
      for (let i = 0; i < cert.attributes.length; i++) {

            if(cert.attributes[i].type == "1.2.840.113549.1.9.14"){        
              let extensions = pkijs.Extensions.fromBER(cert.attributes[i].values[0].toBER(false)).extensions;

              for (let j = 0; j < extensions.length; j++) {
                  if(extensions[j].extnID == "2.5.29.17"){

                       let altNameBin = asn1js.fromBER(extensions[j].extnValue.toBER(false)).result;              
                       let altNames = pkijs.GeneralNames.fromBER(altNameBin.getValue());
                       let altName = altNames.names[0].value;

                       //let altName = altNameBin.valueBlock.value[0].valueBlock.value[0].valueBlock.value[0].valueBlock.value
                       return JSON.parse(altName);
                  }
              }
              break;
            }
    	}
      */
      	return null;
    }

    function certPayloadHasField(cert,fieldName,fieldValue){
        let certPayload = getCertificatePayload(cert);

        if(certPayload != null && Object.keys(certPayload).length>0)
        	return ( certPayload.hasOwnProperty(fieldName) && (  (typeof fieldValue == "undefined") || (certPayload[fieldName] == fieldValue)) );

      	return false;
    }

    function getCertPayloadField(cert,fieldName){
        let certPayload = getCertificatePayload(cert);

        return certPayload[fieldName];
    }


    async function extractIdentityAnchorElement(signedDocument,idAnchorElements){
            
                //does the id anchor cert have an identity anchor element (SSN,DLN..etc) on it
                for(let idElementKey in idAnchorElements)
                {
                  	let mappedSignedDocument = [];
                  
                    let idAnchorEl = idElementKey;
                    let signedAnchorEl = null;
                    for(let i=0;i<signedDocument.length;i++)
                    {
                        let saEl = signedDocument[i];
                        //create a plain hashmap version of document
                        let mappedDocField = {};
                      	mappedSignedDocument.push(mappedDocField);
                      
                      	let mappedDocPlainField = {};
                      	Object.assign(mappedDocPlainField,saEl.plainField);                      
                      	mappedDocField["plainField"]=mappedDocPlainField;                        
                      
                        if(saEl.maskedField)
                      	{
                            let mappedDocMaskedField = {};
                            Object.assign(mappedDocMaskedField,saEl.maskedField);                      
                            mappedDocField["maskedField"]=mappedDocMaskedField;
                      	}
                        //console.log("loop"+i,saEl,idAnchorEl)
                        if(saEl.plainField.name == idAnchorEl)
                        {
                            signedAnchorEl = saEl.plainField.value.toUpperCase().replaceAll("-","").replaceAll(" ","").toUpperCase();                            
                        }
                    }

                    if(signedAnchorEl != null)
                    {
						return {
                          "value":signedAnchorEl,
                          "name":idAnchorEl
                        };
                    }
                }
    }


	export  {
      getCertIssuer,
      getCertIssuerFingerPrint,
      issuerIsPrivate,
      derivationSourceIsPrivate,
      getCertDerivationSourceFingerPrint,
      getCertDerivationSourceIssuerFingerPrint,
      derivationSourceIssuerIsPrivate,
      pemEncodeCert,
      exportCertificate,
      certPayloadHasField,
      getCertPayloadField,
      getCertificatePayload,
      extractCertPublicKey,
      getCertFingerPrint,
      decodeCertificate,
      extractIdentityAnchorElement
    };