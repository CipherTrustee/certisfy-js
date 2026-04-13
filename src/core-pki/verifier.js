	import {asn1js,pkijs} from '../utils/pkijs.js';
	import * as cryptoUtil from '../utils/crypto.js';
    import * as helperUtil from '../utils/helpers.js';
    import * as certUtil from '../utils/cert.js';

	import * as defaultConfig from '../config.js';

	import * as certisfyAPI from '../core-api/api.js';

    import * as claimData from './claim-data.js';
	import * as certStore from './cert-store.js';

	const {isValidString,textToClaimObject,copyFromObject} = helperUtil;
	const {sha2Hex,hmacHex,bobsResponseKeyGen,aliceKeyGen,AES_GCM_CIPHER,base64DecodeToBin} = cryptoUtil;

    const {getDHExchange,postDHExchange,getSignature} = certisfyAPI;
	const {decodeCertificate,getCertificatePayload,getCertIssuerFingerPrint,getCertFingerPrint,issuerIsPrivate,derivationSourceIsPrivate,derivationSourceIssuerIsPrivate,exportCertificate,certPayloadHasField,getCertPayloadField,getCertDerivationSourceFingerPrint,getCertDerivationSourceIssuerFingerPrint} = certUtil;
	const {setPlainFields,hasClaimField,hashPlainField,extractClaimPlainFields,getVerifiedCertificateField,isInternalField,isInternalFieldName,getVouches} = claimData;
	const {getCertFromStore,getCertChainWithStatusFromStore,getCertChainFromStore,getLocalCert,isLocalCert,getCertChainFromLocalStore} = certStore;

    //access to properly configured modules
    let sdk;

	function getConfig(){
    	return sdk?sdk.getConfig():defaultConfig;
    }

    async function buildTrustedCertChain(fingerPrint,useChain){
		let certChainVerification = await buildCertChain(fingerPrint,true,useChain);

        if(certChainVerification.certificateVerified && (certChainVerification.chain.length>1))
      		certChainVerification["certificateVerified"] = await isTrustedChain(certChainVerification.chain);

        return certChainVerification;
    }

   /*
    * chain constructed via this call is what's considered trust chain.
    */
    async function buildCertChain(finger_print,validate,useChain){
        let certChain = [];
        let certVerification = {};
      
        let validChain = true;
        let chain = (useChain && typeof useChain == "object" && !Array.isArray(useChain))?useChain.certs:useChain;
        if(!chain || chain.length == 0){
        	 let trustChain = await getCertChainFromStore(finger_print);
             if(trustChain && trustChain.certs)
               chain = trustChain.certs;
             else
               chain = [];
        }
      
        if(chain.length == 0)
        {
          	console.warn(`Empty trust chain.`);
          	certVerification["certificateVerified"]=false;
        	certVerification["chain"]=[];
        	return certVerification;
        }
      
        let cert = decodeCertificate(chain[0].cert_text);
        chain[0].validFrom = cert.notBefore.value.getTime();
      
        //check valid from
        if(validate && cert.notBefore.value.getTime()>new Date().getTime()){
          //throw new Error(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
          console.warn(`Pretermed certificate in trust chain.`);
          validChain = false;
        }
      
        //check expiry
        if(validate && new Date().getTime()>cert.notAfter.value.getTime()){
          //throw new Error("Expired certificate in certificate chain.");
          console.warn("Expired certificate in certificate trust chain.");
          validChain = false;
        }

        if(validate && (chain[0].status && chain[0].status != "good")){
			console.warn("Revoked certificate in certificate trust chain.");
            validChain = false;
        }
      	//console.log(new Date().getTime(),">",cert.notAfter.value.getTime(),(new Date().getTime()>cert.notAfter.value.getTime()));      	
      	//console.log(new Date(),">",cert.notAfter.value,(new Date().getTime()>cert.notAfter.value.getTime()));      	
      
        let leafCert = cert;
        
        certVerification["certificateVerified"]=false;
        certVerification["chain"]=certChain;
      
        certChain.push(await exportCertificate(leafCert,copyFromObject(chain[0],["issuer_finger_print","derivation_source_finger_print","derivation_source_issuer_finger_print","isTrustworthy"])));
      
        if(chain[0].status){
           certChain[certChain.length-1].status = chain[0].status;
           if(chain[0].status_message)
             	certChain[certChain.length-1].status_message = chain[0].status_message;
          
           if(chain[0].revocation_date)
             	certChain[certChain.length-1].revocation_date = chain[0].revocation_date;
        }
      
        if(chain[0].authority_status){
           certChain[certChain.length-1].authority_status = chain[0].authority_status;
           if(chain[0].authority_status_message)
             	certChain[certChain.length-1].authority_status_message = chain[0].authority_status_message;
          
           if(chain[0].authority_suspension_date)
             	certChain[certChain.length-1].authority_suspension_date = chain[0].authority_suspension_date;
        }
        //console.log(`isTrustChainRoot(finger_print)`,finger_print,isTrustChainRoot(finger_print),validChain)

      	if(isTrustChainRoot(finger_print))
        {
            certVerification["certificateVerified"]= (validate && validChain);
            return certVerification;
        }
      
      
		//for private issuer, verifier needs to rely on PKI
        //platform validation and verify the provided signature attesting to the validity of the
        //chain.
		if(chain.length == 1 && (issuerIsPrivate(chain[0]))){
          
          	let derivedFromCertCertificateVerified = true
            if(certPayloadHasField(leafCert,"pki-cert-is-derived-from") && !derivationSourceIsPrivate(chain[0]))
                derivedFromCertCertificateVerified = (await buildTrustedCertChain(await getCertDerivationSourceFingerPrint(chain[0]))).certificateVerified;              
          
            let isValidPrivateChain = await verifyPrivateCertChain(useChain);
          	//console.log("platform validate",isValidPrivateChain,validate,validChain/*,chain[0].isTrustworthy*/)
			certVerification["certificateVerified"]= ((typeof validate != "undefined" && validate == true) && validChain && isValidPrivateChain && derivedFromCertCertificateVerified /*&& chain[0].isTrustworthy*/);
            return certVerification;
        }
      
        try
        {
            //first verify and build cryptographic chain relationship
            for(let i=1;i<chain.length;i++)
            {
              	let certData = chain[i-1];
                let issuerCertPEM = chain[i].cert_text;

                let certFingerPrint = await getCertFingerPrint(cert);
                let issuerThumbprint = await getCertIssuerFingerPrint(certData)/*.substring(3)*/;
              
                //console.log("Checking issuer:"+issuerThumbprint);

                let issuerCert = decodeCertificate(issuerCertPEM);
                let computedIssuerThumbprint = await getCertFingerPrint(issuerCert);

              	//chain[i].validfrom_date = issuerCert.notBefore.value.getTime();
                if(issuerThumbprint == computedIssuerThumbprint)
                {
                    if(validate && !verifyCertChain([issuerCert,cert]))
                      	throw new Error(`Unable to verify trust chain(${certFingerPrint},${issuerThumbprint})`);

                    //check valid from
                    if(validate && issuerCert.notBefore.value.getTime()>new Date().getTime()){
                      	//throw new Error(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
                        console.warn(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
                        validChain = false;
                    }
                  
                    //check expiry
                    if(validate && new Date().getTime()>issuerCert.notAfter.value.getTime()){
                      	//throw new Error(`Expired certificate(${issuerThumbprint}) in trust chain.`);
                        console.warn(`Expired certificate(${issuerThumbprint}) in trust chain.`);
                        validChain = false;
                    }

                  	if(validate && (chain[i].status && chain[i].status != "good")){
                        console.warn(`Revoked certificate(${issuerThumbprint} in cert trust chain.`);
                        validChain = false;
                    }
                  
                    if(validate && (chain[i].authority_status && chain[i].authority_status != "good")){
                        if(cert.notBefore.value.getTime() >= chain[i].authority_suspension_date){
                            console.warn(`Suspended certificate(${issuerThumbprint} in cert trust chain before certificate was issued.`);
                            validChain = false;
                        }
                    }
                  
                    let exportedCert = await exportCertificate(issuerCert,copyFromObject(chain[i],["issuer_finger_print","derivation_source_finger_print","derivation_source_issuer_finger_print","isTrustworthy"]));
                    certChain.push(exportedCert);
                  
                    if(chain[i].status){
                       certChain[certChain.length-1].status = chain[i].status;
                       if(chain[i].status_message)
                            certChain[certChain.length-1].status_message = chain[i].status_message;
                      
                       if(chain[i].revocation_date)
             				certChain[certChain.length-1].revocation_date = chain[i].revocation_date;
                    }
                  
                    if(chain[i].authority_status){
                       certChain[certChain.length-1].authority_status = chain[i].authority_status;
                       if(chain[i].authority_status_message)
                            certChain[certChain.length-1].authority_status_message = chain[i].authority_status_message;

                       if(chain[i].authority_suspension_date)
                            certChain[certChain.length-1].authority_suspension_date = chain[i].authority_suspension_date;
                    }

                    cert = issuerCert;

                    //console.log(`isTrustChainRoot(computedIssuerThumbprint)`,computedIssuerThumbprint,isTrustChainRoot(computedIssuerThumbprint),validChain)
                    if(isTrustChainRoot(computedIssuerThumbprint))
                    {
                         if(certPayloadHasField(leafCert,"pki-cert-is-derived-from")){
                              //for private derivation source, verifier needs to rely on PKI
                           	  //platform validation and verify the provided signature attesting to the validity of the
                           	  //chain.
                              if(derivationSourceIsPrivate(chain[0])){
                                  let isValidPrivateChain = await verifyPrivateCertChain(useChain);
                                  //console.log("platform validate",isValidPrivateChain,validate,validChain,useChain/*,chain[0].isTrustworthy*/)
                                
                                  certVerification["certificateVerified"]= ((typeof validate != "undefined" && validate == true) && validChain && isValidPrivateChain /*&& chain[0].isTrustworthy*/);
                                  return certVerification;
                              }
							  else
                              {
                                  let derivedFromCertCertificateVerified = (await buildTrustedCertChain(await getCertDerivationSourceFingerPrint(chain[0]))).certificateVerified
                                  
                                  certVerification["certificateVerified"]= ((typeof validate != "undefined" && validate == true) && validChain && derivedFromCertCertificateVerified);
                                  return certVerification;
                              }
                         }
                         else
                         {
                              certVerification["certificateVerified"]= ((typeof validate != "undefined" && validate == true) && validChain);
                              return certVerification;
                         }
                    }
                    continue;
                }
                else
                {
                   throw new Error(`invalid certificate(${issuerThumbprint},${computedIssuerThumbprint}) in trust chain, invalid issuer for ${certFingerPrint}.`);
                }                
            }
			//this means either trust chain root is bypassed or chain is empty
            return certVerification;
        }
        catch(e)
        {
            console.error("buildTrustedCertChain Error",e);
        }

        certVerification["certificateVerified"]=false;
        certVerification["chain"]=[];
        return certVerification;
    }

    async function isIssuedBy(cert,issuer,strictCheck=false){
        let certObject = decodeCertificate(cert.cert_text);
        let issuerCertObject = decodeCertificate(issuer.cert_text);

      	let certThumbprint = await getCertFingerPrint(certObject);
        let issuerThumbprint = await getCertFingerPrint(issuerCertObject);
      
      	if(certThumbprint == issuerThumbprint && strictCheck)
      		return false;

        //console.log("isIssuedBy:"+certObject.verify(issuerCertObject.getPublicKey()));
        //console.log("isIssuedBy:"+(certObject.getIssuerX500Principal() != null && certObject.getIssuerX500Principal().equals(DigestUtils.sha1Hex(issuerCertObject.getEncoded())))+"/"+issuerThumbprint+"/"+certObject.getIssuerX500Principal());
        try
        {              
            if(!verifyCertChain([issuerCertObject,certObject]))
               throw new Error("Unable to verify issuer trust chain.");
          
            //console.log(certThumbprint+" isIssuedBy:"+issuerThumbprint,((await getCertIssuerFingerPrint(cert)) == issuerThumbprint),cert);
            return ((await getCertIssuerFingerPrint(cert)) == issuerThumbprint);
        }
        catch(error)
        {
            console.error(error);
        }

        return false;
    }

   /*
    * A valid trust anchor chain is one that:
    *    -1. either consists of only root 
    *    -2. or consists of only root and leaf, and leaf is issued by root 
    *    -3. or leaf is a delegate to a cert (up chain) that satisfies condition 2.
    *
    * rootCert:chain[chain.size()-1]
    * leafCert:chain[0]
    *
    * conds 1 & 2 makes you a trust anchor, cond 3 makes you a delegate with 
    * the authority to issue trustworthy certs.
    */
    async function isValidTrustAnchorChain(chain){
        if(chain.length <1)
      		return false;

      	if(chain.length == 1)
			return isTrustChainRoot(chain[0].finger_print);
      
        //validate root
        if(!isTrustChainRoot(chain[chain.length-1].finger_print))
      		return false;
      
        //console.log(chain[chain.length-1].cert_text)
        let rootCert = chain[chain.length-1];
        let leafCert = chain[0];

        if(chain.length == 2)//if the leaf cert itself is a trust anchor
            return (await isIssuedBy(leafCert,rootCert));       
		
        leafCert = chain[chain.length-2];
        //validate trust anchor
        if(!(await isIssuedBy(leafCert,rootCert)))
      		return false;

      	//if trust anchor didn't issue it then validate delegation chain
        //skip root and validate the rest of the chain as delegates
        return isValidDelegationChain(chain.toSpliced(chain.length-1,1));
    }  

   /*
    *A chain is trusted if 
    *	1. it is a trust anchor chain or 
    *	2. the leaf is issued by a trust anchor chain
    *
    *possible structures of a trusted chain:
    *	1. root
    *	2. trust anchor>root
    *	3. [one or more delegates]>trust anchor>root>
    *	4. trusted cert>[zero or more delegates]>trust anchor>root
    */
    async function isTrustedChain(chain){
        //cond 1. it is a trust anchor chain, 
        //  a). chain.size() ==1 and chain[0] is root 
        //  b). chain.size() ==2 and chain[1] is root, chain[0] is issued by root (ie trust anchor)
		if(chain.length<3)
      		return isValidTrustAnchorChain(chain);
      
        let issuerCert = chain[1];
        let leafCert = chain[0];
        //cond 2. leaf is issued by a trust anchor chain,
      	//  a). the leaf could itself be a trust anchor delegate, 
      	//	    in that case whole chain is a trust anchor chain.
      	//  b). or leaf is a trusted cert
        //console.log(await isValidTrustAnchorChain(chain),await isValidTrustAnchorChain(chain.slice(1,chain.length)),await isIssuedBy(leafCert,issuerCert))
      	return (await isValidTrustAnchorChain(chain) || (await isValidTrustAnchorChain(chain.slice(1,chain.length)) && await isIssuedBy(leafCert,issuerCert)) );
    }
    
   /*
    * A trust anchor is either, root, a trust anchor (issued by root) or trust anchor delegate.
    * ie the leaf in a trust chain.
    */  
    async function isTrustAnchor(cert,useChain){
        let fingerPrint = await getCertFingerPrint(cert);
		let certChainVerification = await buildCertChain(fingerPrint,true,useChain);
        
        let chain = certChainVerification.chain;
      
      	if(certChainVerification.certificateVerified){
            return  isValidTrustAnchorChain(chain);
        }
        return false;
    }

   /*
    * has right if 
    * 1. it is on a valid trust anchor chain 
    * 2. and the delegationLevel requested is less than pki-maximum-delegates of issuer.
    *
    */
    async function hasDelegationRight(issuerCert,delegationLevel) {
        //cond 1.
        let issuerCertFingerPrint = await getCertFingerPrint(issuerCert);
        if(isTrustChainRoot(issuerCertFingerPrint))
      		return true;
      
      	let trustAnchor = await isTrustAnchor(issuerCert);
		if(!trustAnchor)
      		return false;
      
        //cond 2.
        let issuerCertPayload = getCertificatePayload(issuerCert);  

        //confirm that this would be a valid delegation chain if the delegationLevel is granted
        if(issuerCertPayload["pki-maximum-delegates"] && (parseInt(issuerCertPayload["pki-maximum-delegates"]) > delegationLevel))
        {
            return true;
        }
      	return false;
    }

   /*
    * validation involves
    *	1. Ensure the delegated trust chain length is less than pki-maximum-delegates 
    *	   of trust anchor. chain is rooted at trust anchor.
    *   2. Ensure that cond 1. holds at every level below trust anchor in the 
    *      delegated trust chain. In other words a delegate can only delegate below the level
    *	   of delegation of it's immediate issuer.
    *
    */
    function isValidDelegationChain(chain){
        
        //if issued by a delegate, check that delegation level is valid  
        let delegationLevel = chain.length-1;//move to root of delegation (ie minus trust anchor)
		let cumulativeDelgation = 0;
      
        let trustAnchorCert = decodeCertificate(chain[delegationLevel].cert_text);  
        let trustAnchorCertPayload = getCertificatePayload(trustAnchorCert);  

        //cond 1.
        if(typeof trustAnchorCertPayload["pki-maximum-delegates"] == "undefined" ||
           trustAnchorCertPayload["pki-maximum-delegates"] == null ||
           !(parseInt(trustAnchorCertPayload["pki-maximum-delegates"]) >= delegationLevel) )
        	return false;
      
      	//cond 2.
        //extra sanity check, verify delegation chain
        let parentDelgationLevel = parseInt(trustAnchorCertPayload["pki-maximum-delegates"]);
        
        for(let i=delegationLevel-1; i>=0;i--)
        {
            let issuerCert = decodeCertificate(chain[i].cert_text)
            let issuerCertPayload = getCertificatePayload(issuerCert);
          	
            if(typeof trustAnchorCertPayload["pki-maximum-delegates"] == "undefined" || issuerCertPayload["pki-maximum-delegates"] == null || parseInt(issuerCertPayload["pki-maximum-delegates"])<0)
            	return false;

            if(parseInt(issuerCertPayload["pki-maximum-delegates"]) >= parentDelgationLevel)
          		return false;
          
            parentDelgationLevel = parseInt(issuerCertPayload["pki-maximum-delegates"]);
        }
        
      	return true;
    }

    async function getTrackedSignature(sig_id){
        if(!getConfig().apiInfo.target)
          	return {};
      
      	
        return getSignature(sig_id);
      
      	/*return new Promise((resolve,reject)=>{
            if(!getConfig().apiInfo.target)
               return resolve({})
          
			sendRequest({
              "action":"get-tracked-signature",
              "sig_id":sig_id
            }).then(function(resp){
                resolve(resp);
            })
        }); */  
    }

    function certField(cert,fieldName,fieldVerification){
        for(let i=0;i<fieldVerification.fields.length;i++)
        {
            let fieldContainer=fieldVerification.fields[i];
          
			if(fieldContainer.plainField[fieldName])
            {
				if(fieldContainer.plainField.certificateVerified)
                {
                    if(fieldContainer.maskedField)
                  	{
                        if(fieldContainer.maskedField.certificateVerified)
                            return fieldContainer.plainField[fieldName];    
                  	}
                    else
                    return fieldContainer.plainField[fieldName];                  
                }
              	break;
            }
        }
      	return null;
    }

    async function isIdentityCert(cert,fieldVerification){
      
        //id anchor cert must be issued by trust anchor
        let certVerification = await buildTrustedCertChain(cert.finger_print);
        if(!certVerification.certificateVerified)
        	return false;

        let trustChain = certVerification.chain;
      
        //does the id anchor cert have an identity anchor element (SSN,DLN..etc) on it
        for(let idElementKey in getConfig().idAnchorElements)
        {
			let idElement = certField(cert,idElementKey,fieldVerification);
            if(idElement != null)
            {
				return true;
            }
        }
      	return false;
    }

   /*
    *This is to represent the PKI platform root...**should be revisited**
    */
    function isTrustRoot(fingerPrint){           
      	return (fingerPrint == getConfig().trustRoots[0].finger_print);
    }  
  
    function isTrustChainRoot(fingerPrint){
      	//console.log("isTrustChainRoot",getConfig().trustRoots,sdk.getConfig().trustRoots);
      	//return (getConfig().trustChainRoot.finger_print == fingerPrint);
      	return ((getConfig().trustRoots && getConfig().trustRoots.find(c=>c.finger_print == fingerPrint))?true:false);
    }

    function isTrustAnchorCert(cert,disallowDemoCert){
        if(disallowDemoCert && cert.finger_print == getConfig().demoTrustAnchorFingerprint)
            return Promise.resolve(false);

        return new Promise(async (resolve,reject)=>{
            resolve(await isTrustAnchor(cert.cert_text))
        });
    }

	function isValidDHExchange(userCode,dhExchange,verification){
        let dhxNonce = getVerificationField(verification,"pki-dhx-nonce");

        if(dhxNonce){
          dhxNonce = dhxNonce.plainField["pki-dhx-nonce"];
          return (dhxNonce == (userCode+"-"+dhExchange.create_date));
        }
        return false;
    }

    async function initiateDHExchange(receiverId,useKeyPair){
        const dhKeyPair = useKeyPair?useKeyPair:(await aliceKeyGen("P-256"));
        let alice_data = receiverId?{"sp_uri":receiverId}:null;

      	let reqParams = {
            "alice_public_key":dhKeyPair.publicKeyBase64
        };
      	if(alice_data)
      		reqParams["alice_data"] = JSON.stringify(alice_data);

        const resp = await postDHExchange(reqParams)
        
        if(resp.status == "success")
        {
            return {
              "status":"success",
              "dhExchange":{
              "create_date":new Date().getTime(),
              "user_code":resp.userCode,
              "private_key":dhKeyPair.privateKeyBase64
            }}
        }      
        return resp; 
    }

    async function verifyCertificateFields(signedString,signer,detachedPlainFields,contextLeafCert){
        let fieldVerification    = {"fields":[]};

        let signedStringPayloadText = signedString.substring(0,signedString.lastIndexOf("timestamp"));
        let signedPayload;
      
        if(!signedStringPayloadText.trim().startsWith("{") || !signedStringPayloadText.trim().endsWith("}"))
          	return fieldVerification;
      
        try
        {
        	signedPayload = JSON.parse(signedStringPayloadText);
        }
      	catch(error){
        	console.warn(`Failed to parse signedString for certificate field verification. ${error}`)
            return fieldVerification;
        }

        let isDetachedPlainFields = (typeof signedPayload.plainFields == "undefined" || signedPayload.plainFields == null);
      
      	let plainFields = !isDetachedPlainFields?signedPayload.plainFields:detachedPlainFields;
      
        if(plainFields)
        {
            let hmacKeys = plainFields.find(f=>f["pki-hmac-keys"])
            if(hmacKeys)
            	hmacKeys = JSON.parse(hmacKeys["pki-hmac-keys"]);
          
          	//exec.logger().info("verifyCertificateFields input fields:"+signedPayload.plainFields.size());
            for(let i=0;i<plainFields.length;i++)
            {
               let plainField = plainFields[i];
               let signedField = await findSignedFieldPeer(plainField,signedPayload,(hmacKeys?hmacKeys[i]:null));
              
               //ensure there is a match within signature, otherwise it is just junk tagged onto detached plainFields
               if(signedField)
               		fieldVerification.fields.push(signedField);
            }
        }
      
        let isEmptyClaim = typeof signedPayload.maskedFields == "undefined" || signedPayload.maskedFields == null;
      
        //if we're using plainFields detached from signature, ensure they haven't been tampered with
        if(isDetachedPlainFields && ((isEmptyClaim && fieldVerification.fields.length>0) || (!isEmptyClaim && signedPayload.maskedFields.length != fieldVerification.fields.length) )){
            //fieldVerification.fields = [];
            //fieldVerification["certificateVerified"]=false;
        	//return fieldVerification;
            console.warn(fieldVerification,plainFields,signedPayload)
            throw new Error("Signature tampering detected.")
        }

      	//exec.logger().info("verifyCertificateFields result:"+fieldVerification.fields.size()+",signedPayload.plainFields:"+signedPayload.plainFields);
        fieldVerification["certificateVerified"]=await verifyDocument(signer,fieldVerification.fields,false,contextLeafCert);
        return fieldVerification;
    }

    async function findSignedFieldPeer(field,signedPayload,hmacKey){
        /*
          TODO: Fix this function, it currently combines signature validation with hmac validation.
          hmac validation should happen only at data use stage, for instance when displaying on client ui
          or left to be performed by a service provider before accepting plain data attached to claims.
          
          Ultimately the goal of this function is to help ensure supplied data (plain or masked) matches signed data, ie prevent
          tampering.
        */
        let fieldName = Object.keys(field)[0];
        let fieldValue = field[fieldName];

      	if(signedPayload.maskedFields){
            for(let i=0;i<signedPayload.maskedFields.length;i++)
            {
                let maskedField = signedPayload.maskedFields[i];
              
                if(false && typeof maskedField["hmacKey"] == "undefined"){//treat it as a plain field...or already hmaced...**UNFINISHED business**
                    
                    let plainFieldName = Object.keys(maskedField)[0];
                    let plainFieldValue = maskedField[plainFieldName];

                    if(fieldName == plainFieldName && fieldValue == plainFieldValue)
                    {
                        let verifiedField = {};

                        let m = Object.assign({},plainField);
                        verifiedField["plainField"]=m;           
                        return verifiedField;
                    }
                }
                else
                {
                    for(let maskedFieldName in maskedField){

                        let maskedFieldValue = maskedField[maskedFieldName];
						if(!maskedFieldValue || !maskedFieldName || !isValidString(fieldValue) || !isValidString(fieldName))
                      		continue;
                      
                        if(true /*maskedFieldName != "hmacKey"*/)
                        {
                            //const hmacKey = hmacKeyMask && hmacKeyMask.hasOwnProperty(maskedField.hmacKey)?hmacKeyMask[maskedField.hmacKey]:maskedField.hmacKey;
                          
                            let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(field,getConfig().PUBLIC_PLAIN_FIELDS,null,false,hmacKey);
                            //perform hmac on plain data...future changes to this function should remove this approach
                            const dataIsHMACValidated = (fieldNameHash == maskedFieldName &&  fieldValueHash == maskedFieldValue)
                            //const dataIsHMACValidated = (hmacKey && hmacKey.length >0 && hmacHex(hmacKey,fieldNameHash) == maskedFieldName &&  hmacHex(hmacKey,fieldValueHash) == maskedFieldValue)

                            let {fieldName:fieldNameHash1,fieldValue:fieldValueHash1} = await hashPlainField(field,getConfig().PUBLIC_PLAIN_FIELDS,null,false,hmacKey,true);
                            //perform hmac on hashed data...future changes to this function should remove this approach
                            const dataHashIsHMACValidated = (fieldNameHash1 == maskedFieldName &&  fieldValueHash1 == maskedFieldValue)

                            //assume data was hmaced before being included...this is better for privacy and doesn't require exposing
                            //hmac key to validation routine.
                            const dataIsHMACed = (fieldName == maskedFieldName && fieldValue == maskedFieldValue);
                            //const dataIsHMACed = (hmacHex(hmacKey,fieldName) == maskedFieldName && hmacHex(hmacKey,fieldValue) == maskedFieldValue);
                            
                            //console.log("findSignedFieldPeer:",fieldNameHash,fieldValueHash,hmacHex(hmacKey,fieldValue),hmacHex(hmacKey,fieldValueHash),fieldName,fieldValue);
                            //console.log("mask test fieldName:"+fieldName+"/"+hmacHex(maskedField.hmacKey,fieldName)+","+hmacHex(maskedField.hmacKey,fieldValue));
                            if(dataIsHMACed || dataHashIsHMACValidated || dataIsHMACValidated)
                            {
                                //console.log("passed mask test fieldName:"+fieldName+"/"+hmacHex(maskedField.hmacKey,fieldName)+","+hmacHex(maskedField.hmacKey,fieldValue));
                                let verifiedField = {};

                                let m = Object.assign({},field);
                                verifiedField["plainField"]=m;

                                m = Object.assign({},maskedField);
                                verifiedField["maskedField"]=m;
                              
                                //this is a hack to accomodate existing private certificates that have an hmac of their 
                                //corresponding plainFields instead of an hmac of the hash of their corresponding plainFields.
                                if(false && !(hmacHex(hmacKey,fieldName) == maskedFieldName && hmacHex(hmacKey,fieldValue) == maskedFieldValue)){                                  
                                    verifiedField["unhashedMaskedField"] = {[hmacHex(hmacKey,fieldName)]:hmacHex(hmacKey,fieldValue),"hmacKey":hmacKey};
                                }
                                return verifiedField;
                            }
                          	//else
                            //if(fieldName.startsWith("pki-plain-fields:"))
                            //  	console.log(maskedField,JSON.parse(fieldValueHash),JSON.parse(fieldValueHash1))
                        }
                    }
                }
            }
        }      

      	if(signedPayload.plainFields){
            for(let i=0;i<signedPayload.plainFields.length;i++)
            {
                let plainField = signedPayload.plainFields[i];
              
                let plainFieldName = Object.keys(plainField)[0];
                let plainFieldValue = plainField[plainFieldName];
              
				if(!isValidString(plainFieldName) || !isValidString(plainFieldValue) || !isValidString(fieldValue) || !isValidString(fieldName))
                   continue;
              
                if(fieldName == plainFieldName && fieldValue == plainFieldValue)
                {
                    //exec.logger().info("passed mask test fieldName:"+fieldName+"/"+hmacUtil.hmacHex(fieldName)+","+hmacUtil.hmacHex(fieldValue));
                    let verifiedField = {};

                    let m = Object.assign({},plainField);
                    verifiedField["plainField"]=m;           
                    return verifiedField;
                }
            }
        }

		return null;
    }

    function verifyCertChain(chain){
          //create new X.509 certificate chain object
          const certChainVerificationEngine = new pkijs.CertificateChainValidationEngine({
              trustedCerts:chain[0],//trusted cert
              certs: chain.slice(1,chain.length),//chain to verify
              crls:[],//revocations
          });
          return certChainVerificationEngine.verify();      
    }

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//for private cert chains (ex: private issuer or private derivation source), verifier needs to rely on PKI
    //platform validation and verify the provided signature attesting to the validity of the chain.
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	async function verifyPrivateCertChain(trustChain){
      	if(!trustChain || typeof trustChain != "object" || Array.isArray(trustChain))
          	return false;
      
      	let validChain = true;
      
      	if(!trustChain.validfrom_date || !trustChain.expiration_date){
            if(trustChain.certs.length == 1 && issuerIsPrivate(trustChain.certs[0])  && isLocalCert(trustChain.certs[0]))//allow this, it useful for testing 
              return true;
          
          	return false;
        }
      
        //check valid from
        if(trustChain.validfrom_date>new Date().getTime()){
          //throw new Error(`Pretermed certificate(${issuerThumbprint}) in trust chain.`);
          console.warn(`Pretermed certificate in private trust chain.`);
          validChain = false;
        }
      
        //check expiry
        if(new Date().getTime()>trustChain.expiration_date){
          //throw new Error("Expired certificate in certificate chain.");
          console.warn(`Expired certificate in private trust chain.`);
          validChain = false;
        }
      
      	const signedString = [];
      
      	for(const cert of trustChain.certs){
      		signedString.push(cert.finger_print);
        }
      
      	signedString.push(trustChain.validfrom_date);
        signedString.push(trustChain.expiration_date);
      
        signedString.push(trustChain.isValid);
        signedString.push(trustChain.isTrustworthy);
      
      	if(typeof trustChain.isTrustedDerivation != "undefined")
          	signedString.push(trustChain.isTrustedDerivation);

      	signedString.push(`timestamp=${trustChain.signature.timestamp}`);
      
      	for(const rootCert of getConfig().trustRoots){
            const signerCert = decodeCertificate(/*getConfig().trustChainRoot.cert_text*/rootCert.cert_text);
            let verified = await verifyText(signedString.join(""),trustChain.signature.signature,signerCert);
			//console.log(`checking root ${rootCert.finger_print},${verified},${validChain}`,trustChain)
          	if(verified)
            	return (validChain && verified && trustChain.isValid && trustChain.isTrustworthy && (typeof trustChain.isTrustedDerivation == "undefined" || trustChain.isTrustedDerivation == true));
        }
      	return false;
    }
    
	async function verifyDocument(signer,fields,flatten,contextLeafCert,hmacKeyMask){
      
        let signerCert = contextLeafCert;
      
        if(!signerCert){
            signerCert = typeof signer == "string"?await getCertFromStore(signer):signer;
            signerCert = typeof signer == "string"?signerCert.cert_text:signerCert;
        }
      	else
        {
          	//signerCert = await exportCertificate(signerCert);
        }
      
        if(fields.length == 0)
            return false;

        let verified = true;
        let payloadObject = getCertificatePayload(signerCert);
      
        if(payloadObject == null)
            return false;

      	let updatedFields = [];
        
        for(let i=0;i<fields.length;i++)
        {
            let  fieldContainer = fields[i];

            let plainField = fieldContainer.plainField;
            let maskedField = fieldContainer.maskedField;
          	let unhashedMaskedField = fieldContainer.unhashedMaskedField;

            let updatedFieldContainer = {};
            updatedFields.push(updatedFieldContainer);

          	let updatedPlainField = {};
          	let updatedMaskedField = {};
            let updatedUnhashedMaskedField = {};

          	if(plainField)
          	{
                Object.assign(updatedPlainField,plainField);
                updatedFieldContainer["plainField"]=updatedPlainField;
          	}

          	if(maskedField)
            {
                Object.assign(updatedMaskedField,maskedField); 
                updatedFieldContainer["maskedField"]=updatedMaskedField;
            }
          
            if(unhashedMaskedField)
            {
                Object.assign(updatedUnhashedMaskedField,unhashedMaskedField); 
                updatedFieldContainer["unhashedMaskedField"]=updatedUnhashedMaskedField;
            }

            let useMaskedField = unhashedMaskedField?unhashedMaskedField:maskedField;

            if(fieldContainer.maskedField)
            {
                if(flatten)
                {
                    let flattenMaskedField = {};
                    flattenMaskedField[useMaskedField.name]=useMaskedField.value;
                    flattenMaskedField["hmacKey"]=hmacKeyMask && hmacKeyMask.hasOwnProperty(useMaskedField.hmacKey)?hmacKeyMask[useMaskedField.hmacKey]:useMaskedField.hmacKey;
                    useMaskedField = flattenMaskedField;
                }

                for (let fieldName in useMaskedField)
                {
                    let fieldValue 	= useMaskedField[fieldName];
                    if(fieldName != "hmacKey")
                    {
                        if(typeof payloadObject[fieldName] != "undefined" && payloadObject[fieldName]==fieldValue)
                        {
                            updatedMaskedField["certificateVerified"]=true;
                            updatedPlainField["certificateVerified"]=true;
                        }
                        else
                        {
                            updatedMaskedField["certificateVerified"]=false;
                            updatedPlainField["certificateVerified"]=false;
                            verified = false;
                        }
                    }        
                }
            }
            else              
            {
                if(flatten)
                {
                    let flattenPlainField = {};
                    flattenPlainField[plainField.name]=plainField.value;
                    plainField = flattenPlainField;
                }

                for (let fieldName in plainField)
                {
                    let fieldValue 	= plainField[fieldName];
                    if(typeof payloadObject[fieldName] != "undefined" && payloadObject[fieldName]==fieldValue)
                    {
                      	updatedPlainField["certificateVerified"]=true;
                    }
                    else
                    {
                        updatedPlainField["certificateVerified"]=false;
                        updatedPlainField["certificateVerificationFailure"]="name/value pair mismatch";
                        verified = false;
                    }
                }
            }
        }

      	fields.splice(0,fields.length);
      	fields.push(...updatedFields);

        return verified;
    }

  	async function verifySignatureExpiry(signaturePayload,signatureVerification){
      
      	signatureVerification["signatureExpirationStatus"]="unspecified";
        signatureVerification["signatureValidFromStatus"]="unspecified";
      
        let signedStringText 	= signaturePayload.signedString.substring(0,signaturePayload.signedString.lastIndexOf("timestamp"));
        let signedStringObject;
      	let plainFields;
      
        if(signedStringText.trim().startsWith("{") && signedStringText.trim().endsWith("}"))
        {
              try
              {
                  /*signedStringObject   = JSON.parse(signedStringText);
                  plainFields = signedStringObject.plainFields?signedStringObject.plainFields:signaturePayload.plainFields;*/
                  plainFields = await extractClaimPlainFields(signaturePayload,signatureVerification);
              }
              catch(error){
                  console.warn(`Failed to parse signedString for certificate expiry verification. ${error}`)
              }
        }
      
      	//check valid from time if present
        if(hasClaimField("pki-valid-from-time",signatureVerification.fieldVerification.fields)){
            let validfromField = getVerifiedCertificateField("pki-valid-from-time",signatureVerification.fieldVerification.fields,true);
            if(validfromField == null){
                signatureVerification["signatureValidFromStatus"]="invalid";
            }
          	else
            {
                let validfromDateText = validfromField["pki-valid-from-time"].substring(0,validfromField["pki-valid-from-time"].indexOf(" ")).trim();
                let validfromTimeText = validfromField["pki-valid-from-time"].substring(validfromField["pki-valid-from-time"].indexOf(" ")).trim();

                let validfromDateTime = new Date();
                validfromDateTime.setUTCFullYear(parseInt(validfromDateText.split("/")[2]),parseInt(validfromDateText.split("/")[0])-1,parseInt(validfromDateText.split("/")[1]));
                validfromDateTime.setUTCHours(parseInt(validfromTimeText.split(":")[0].trim()));
                validfromDateTime.setUTCMinutes(parseInt(validfromTimeText.split(":")[1].trim()));              

                if(validfromDateTime.getTime()>new Date().getTime())
                  signatureVerification["signatureValidFromStatus"]="pretermed";
                else
                  signatureVerification["signatureValidFromStatus"]="valid";
            }
        }
      
      	//check expiration time if present
        if(hasClaimField("pki-expiration-time",signatureVerification.fieldVerification.fields)){
            let expiryField = getVerifiedCertificateField("pki-expiration-time",signatureVerification.fieldVerification.fields,true);
            if(expiryField == null){
                signatureVerification["signatureExpirationStatus"]="invalid";
            }
          	else
            {
                let expireDateText = expiryField["pki-expiration-time"].substring(0,expiryField["pki-expiration-time"].indexOf(" ")).trim();
                let expireTimeText = expiryField["pki-expiration-time"].substring(expiryField["pki-expiration-time"].indexOf(" ")).trim();
                let expireDateTime = new Date();
                expireDateTime.setUTCFullYear(parseInt(expireDateText.split("/")[2]),parseInt(expireDateText.split("/")[0])-1,parseInt(expireDateText.split("/")[1]));
                expireDateTime.setUTCHours(parseInt(expireTimeText.split(":")[0].trim()));
                expireDateTime.setUTCMinutes(parseInt(expireTimeText.split(":")[1].trim()));              

                if(expireDateTime.getTime()<new Date().getTime())
                  signatureVerification["signatureExpirationStatus"]="expired";
                else
                  signatureVerification["signatureExpirationStatus"]="valid";
            }
        }
    }

  	async function verifyPKIIdentity(signaturePayload,signatureVerification,spUri){
            let identityPayload   = signaturePayload["pki-identity"];
            
      		//console.log("pki-identity",identityPayload,signatureVerification,spUri);
            if(identityPayload)
            {
                let platformSignerCert = decodeCertificate(getConfig().trustRoots[0].cert_text);

                if(identityPayload.cloaked_token)//for stickers
                {
                        //identity (relative to certisfy.com as service provider) is validated before sticker is issued
                  		signatureVerification["pkiIdentityReceiverMatch"]=true;
                  
                        //this works for server-side additional validation 
                  		/*
                      	let signatureEmbed = await getEmbededSignature(identityPayload.embed_id);
                        if(signatureEmbed != null)
                        {
                            let cloakedIdentity = await pkiHMAC([identityPayload.embed_id,[signaturePayload.signature]]);
                            if(cloakedIdentity != identityPayload.cloaked_token){//ensure the token is for this signature
                                  return;
                            }

                            let signatureEmbedObject = JSON.parse(signatureEmbed.signatureEmbed);
                            let signedStringText 	= signatureEmbedObject.signedString.substring(0,signatureEmbedObject.signedString.lastIndexOf("timestamp"));
                            let signedStringObject   = JSON.parse(signedStringText);

                            //get actual identity information
                            for(let i=0;i<signedStringObject.plainFields.length;i++)
                            {
                                let plainField = signedStringObject.plainFields[i];

                                if(typeof plainField.embeddedSignature != "undefined" && plainField.embeddedSignature != null)
                                {
                                    let cloakedIdentityPayload = identityPayload;
                                    let embeddedSignatureObject = JSON.parse(plainField.embeddedSignature);
                                    identityPayload = embeddedSignatureObject["pki-identity"];

                                    let coSignature = identityPayload["pki-cosignature"];
                                  	if(coSignature.signatureP1363)
                                      	coSignature.signature = coSignature.signatureP1363;
                                  
                                    let identitySigString = identityPayload["pki-id-anchor-element"]+identityPayload["pki-sp-id-anchor-token"]+identityPayload["pki-sp-identifier"]+signaturePayload.signature+"timestamp="+coSignature.timestamp;
                                    signatureVerification["pkiIdentityVerified"]= await verifyText(identitySigString,coSignature.signature,platformSignerCert);
                                    signatureVerification["pki-identity"]=cloakedIdentityPayload;                                  

                                    //if an spUri is provided, confirm that the identity spUri matches
                                    if(typeof spUri != "undefined" && spUri != null && spUri.length>0 && !spUri.includes(identityPayload["pki-sp-identifier"]))
                                        signatureVerification["pkiIdentityReceiverMatch"]=false;
                                    else
                                        signatureVerification["pkiIdentityReceiverMatch"]=true;

                                    break;
                                }
                            }
                         }
                        */
                }
                else
                {
                    let coSignature = identityPayload["pki-cosignature"];
                  	if(coSignature.signatureP1363)
                          coSignature.signature = coSignature.signatureP1363;
                  
                    let identitySigString = (identityPayload["pki-sp-id-anchor-token-persona"]?identityPayload["pki-sp-id-anchor-token-persona"]:"")+identityPayload["pki-id-anchor-element"]+identityPayload["pki-sp-id-anchor-token"]+identityPayload["pki-sp-identifier"]+signaturePayload.signature+"timestamp="+coSignature.timestamp;
                    signatureVerification["pkiIdentityVerified"]=await verifyText(identitySigString,coSignature.signature,platformSignerCert);                
                    signatureVerification["pki-identity"]=identityPayload;
                    
                    //if an spUri is provided, confirm that the identity spUri matches
                    if(typeof spUri != "undefined" && spUri != null/* && spUri.length>0*/ /*&& !spUri.includes(identityPayload["pki-sp-identifier"])*/){
                        let hashes = [];
                        for(let i=0;i<spUri.length;i++){
                          	if(spUri[i].startsWith("hash:"))
                              	hashes.push(spUri[i].substring(spUri[i].indexOf(":")+1))
                            else
                          		hashes.push(await sha2Hex(spUri[i]));
                        }
                      
                        signatureVerification["pkiIdentityReceiverMatch"]= (typeof hashes.find(uri=>(uri == identityPayload["pki-sp-identifier"] )) != "undefined");
                    }
                    else//??should this be false or true
                        signatureVerification["pkiIdentityReceiverMatch"]=true;
                  
                    //console.log(signatureVerification,identitySigString);
                }
            }
    }

    async function verifyClaim(signaturePayloadText,spUri=null,useChain=null){
            try
            {
                let signaturePayload   = typeof signaturePayloadText == "string"?JSON.parse(signaturePayloadText):signaturePayloadText;
                signaturePayload 	   = setPlainFields(signaturePayload);
              
                let signedStringPayloadText 	= signaturePayload.signedString.substring(0,signaturePayload.signedString.lastIndexOf("timestamp"));

              	let trustChain = useChain;
                if(typeof useChain == "boolean" && useChain && signaturePayload.trustChain)
                   trustChain = signaturePayload.trustChain;                  	
              
                if((!trustChain || trustChain.certs.length == 0)){
                    trustChain = await getCertChainFromStore(signaturePayload.signerID);
                    /*
                    trustChain = await getCertChainFromStore(signaturePayload.signerID);//NOTE:might contain local leaf cert
                                      
                    if((trustChain.length == 0 || trustChain[0].fromLocalStore) && (!signaturePayload.trustChain || signaturePayload.trustChain.length < 2)){//attempt to build the full chain by concat of issuer chain and provided leaf
                       trustChain = await getCertChainFromStore(await getCertIssuerFingerPrint(signerCert));
                       trustChain.unshift(await exportCertificate(signerCert));
                    }
                  	else
                    if(trustChain.length == 0)
                       trustChain = signaturePayload.trustChain;
                    */
                }
              	else//any supplied trust chain must start with leaf
                {
                     //isTrustworthy on individual certs is only valid if it comes directly from registry
                     if(trustChain){
                         for(const cert of trustChain.certs){
                            delete cert["isTrustworthy"]//don't allow user supplied value
                         }
                     }
                  
                     if(!isTrustChainRoot(trustChain.certs[trustChain.certs.length-1].finger_print) /*getConfig().trustChainRoot && trustChain.certs[trustChain.certs.length-1].finger_print != getConfig().trustChainRoot.finger_print*/){//get the rest of the trust chain

                         const resolveFullChain = async ()=>{
                             let issuerFingerprint = await getCertIssuerFingerPrint(trustChain.certs[trustChain.certs.length-1]);                     
                             let trustChainRemainder = await getCertChainFromStore(issuerFingerprint?issuerFingerprint:trustChain.certs[trustChain.certs.length-1].finger_print);
                             trustChain.certs.push(...trustChainRemainder.certs);
                             trustChain.certs = await getCertChainWithStatusFromStore(trustChain.certs);                         
                         }
                       
						 if(issuerIsPrivate(trustChain.certs[0]) || derivationSourceIsPrivate(trustChain.certs[0]) || derivationSourceIssuerIsPrivate(trustChain.certs[0])){
                             //get latest registry status information
						     let chain = await getCertChainWithStatusFromStore(trustChain.certs);
                           
                             if(!derivationSourceIsPrivate(chain[0])){//derivation source is no longer private                                
                                trustChain.certs[0].derivation_source_finger_print = chain[0].derivation_source_finger_print;                                
                             }
                           
                             if(!derivationSourceIssuerIsPrivate(chain[0])){//derivation source issuer is no longer private                                
                                trustChain.certs[0].derivation_source_issuer_finger_print = chain[0].derivation_source_issuer_finger_print;                                
                             }
                           
                           
                           	 if(!issuerIsPrivate(chain[0])){//issuer is no longer private                                
                                trustChain.certs[0].issuer_finger_print = chain[0].issuer_finger_print;                                
                                await resolveFullChain()
                             }
                             else
                             { 
                                trustChain.certs = [chain[0]];
                             }
                         }
                         else
                         {
							 await resolveFullChain()
                         }
                     }
                }
              
                let signerCert = trustChain && trustChain.certs.length>0?trustChain.certs[0]:await getCertFromStore(signaturePayload.signerID);
                
                if(!signerCert){
                    let signatureVerification = {};
                    signatureVerification["signatureVerified"]=false; 
                    signatureVerification["errorMessage"] = "No certificate found to verify claim";
                    return signatureVerification;
                }
              
                signerCert = decodeCertificate(signerCert.cert_text);
                let verified = await verifyText(signaturePayload.signedString,signaturePayload.signature,signerCert);

                let signatureVerification 	= {
                  "certisfy_object":true,
                  "signedString":signaturePayload.signedString,
                  "signerID":signaturePayload.signerID,
                  "signature":signaturePayload.signature,
                  "signatureVerified":verified
                };

                signatureVerification["certChainVerification"]= (await buildTrustedCertChain(signaturePayload.signerID,trustChain));

                if(signatureVerification["certChainVerification"].chain.length>0)
                  	signatureVerification["certificateIsTrustAnchor"] = (await isTrustAnchor(signatureVerification["certChainVerification"].chain[0].cert_text,trustChain.certs));

                signatureVerification["fieldVerification"]=await verifyCertificateFields(signatureVerification.signedString,signatureVerification.signerID,signaturePayload.plainFields,signerCert);

              
				await verifyPKIIdentity(signaturePayload,signatureVerification,(spUri && typeof spUri == "string" && spUri.length>0?[spUri]:spUri));   
              	await verifySignatureExpiry(signaturePayload,signatureVerification);
              
                let timeStamp = signaturePayload.signedString.substring(signaturePayload.signedString.lastIndexOf("timestamp")+10).trim();
                signatureVerification["timestamp"]=timeStamp;
              
                const trackedSig = await getTrackedSignature(await sha2Hex(signaturePayload.signature));
              	if(trackedSig.sig && trackedSig.sig.status && trackedSig.sig.status.length>0 && trackedSig.sig.status != "good"){
                  	signatureVerification["sigStatusVerification"] = trackedSig.sig.status;
                    signatureVerification["sigStatusVerificationMessage"] = trackedSig.sig.status_message;
                }

                //console.log(signatureVerification)
                return signatureVerification;
            }
            catch(e)
            {
                console.error("verifySignature Error",e);
            }

            let signatureVerification = {};
            signatureVerification["signatureVerified"]=false; 
            return signatureVerification;
    }

	async function verifyDHExchangeClaim(userCode,alicePrivateKey,useDHExchange,spUri=null,useChain=null){
        let dhExchange =  useDHExchange;
        if(!dhExchange){
          const dhResp = await getDHExchange(userCode);
          if(dhResp.status && dhResp.status != "success")
             return {error:dhResp};
          
          dhExchange =  dhResp;
        }
      
        const dhKey 		= await bobsResponseKeyGen(dhExchange.bob_public_key,{"publicKey":dhExchange.alice_public_key,"privateKey":alicePrivateKey});
        const claim 		= JSON.parse(await AES_GCM_CIPHER.decryptMessage(dhKey.AESKey,dhExchange.bob_data));

      	const verification  = await verifyClaim(claim,spUri,useChain||claim.trustChain);
        verification["failedDHExchangeNonceValidation"] = !isValidDHExchange(userCode,dhExchange,verification);

      	return {verification,claim};
    }

    async function getValidVouches(presentingClaim,docVerificationContext){

        return new Promise(async (resolve,reject)=>{
            let validVouchedClaims = [];
            if(presentingClaim["pki-identity"] && presentingClaim["pki-identity"]["pki-vouched-claim-ownership"]){

                const vouchOwnershipSig = presentingClaim["pki-identity"]["pki-vouched-claim-ownership"];

                verifyClaim(vouchOwnershipSig.signature,null,vouchOwnershipSig.signature.trustChain).then( async (signature)=>{
                    if(!signature.signatureVerified){
                        console.warn(`Unable to verify vouched ownership signature for presenting claim. ${signature.errorMessage?signature.errorMessage:""}`)
                        resolve(validVouchedClaims);
                        return;
                    }

                    const signedStringBuf = [];
                    for(const hash of vouchOwnershipSig.identities){
                        signedStringBuf.push(hash);
                    }
                    signedStringBuf.push(presentingClaim["pki-identity"]["pki-cosignature"].signature);              

                    const vouchSignString = await sha2Hex(signedStringBuf.join(""));//await sha2Hex(JSON.stringify(vouchOwnershipSig.identities)+vouchOwnershipSig.signature.signature);
                    if(!vouchOwnershipSig.signature.signedString.startsWith(vouchSignString)){
                        console.warn(`Unable to verify vouched ownership signature for presenting claim. Identity hash doesn't match signature.`)
                        resolve(validVouchedClaims);
                        return;
                    }


                    let presentingClaimPlainFields = await extractClaimPlainFields(presentingClaim,docVerificationContext);
                    //console.log("presentingClaimPlainFields",presentingClaimPlainFields,presentingClaim,docVerificationContext)
                    for(const vouchEntry of (await getVouches(presentingClaimPlainFields))){

                          //spoof receiver so identity verification succeeds, it doesn't matter for this verification type
                          let receiverId = vouchEntry.vouch["pki-identity"]?[`hash:${vouchEntry.vouch["pki-identity"]["pki-sp-identifier"]}`]:null;

                          let sig = await verifyClaim(vouchEntry.vouch,receiverId,vouchEntry.vouch.trustChain)

                          if(!sig.signatureVerified){
                              console.warn(`Unable to verify vouch signature for presenting claim  from signer ${sig.signerID}. ${sig.errorMessage?sig.errorMessage:""}`)
                              continue;
                          }

                          let isTrustAnchor = (await isTrustAnchorCert(sig.certChainVerification.chain[0]));

                          if(!isTrustAnchor && !isClaimTrustworthy(sig)){
                              console.warn(`Unable to verify vouch signature for presenting claim from signer ${sig.signerID}. Vouch claim is not trustworthy.`)
                              continue;
                          }                      

                          const claims = [];
                          for(const claim of vouchEntry.claims){
                              if(!claim["pki-identity"] || !claim["pki-identity"]["pki-owner-id-info-cloak"]){
                                  console.warn(`Unable to match a vouched claim with signer ${claim.signerID}, it lacks an identity.`)
                                  continue;
                              }

                              //ensure the vouched for claim is owned by the presenting claim owner
                              if(!vouchOwnershipSig.identities.includes(claim["pki-identity"]["pki-owner-id-info-cloak"])){
                                  console.warn(`Unable to link a vouched claim identity (${claim["pki-identity"]["pki-owner-id-info-cloak"]}) to presenting claim owner. The vouched claim signer is ${claim.signerID}`)
                                  continue;
                              }

                              //spoof receiver so identity verification succeeds, it doesn't matter for this verification type
                              let receiverId = claim["pki-identity"]?[`hash:${claim["pki-identity"]["pki-sp-identifier"]}`]:null;

                              let sig = await verifyClaim(claim,receiverId,claim.trustChain)

                              if(!sig.signatureVerified){
                                  console.warn(`Unable to verify vouch claim signature for presenting claim from signer ${claim.signerID}. ${sig.errorMessage?sig.errorMessage:""}`)
                                  continue;
                              }

                              if(!isClaimTrustworthy(sig)){
                                  console.warn(`Unable to verify vouch claim signature for presenting claim from signer ${claim.signerID}. Vouched claim is not trustworthy.`)
                                  continue;
                              }

                              if(false && claim.hashedPlainFields)
                                  await unmaskFieldVerifications(sig,(await extractClaimPlainFields(claim)));

                              //treat all trust anchor vouches as trustworthy, essentially as certified certificate fields
                              if(isTrustAnchor){                            
                                  for(const field of sig.fieldVerification.fields){
                                     field.plainField["certificateVerified"] = true;
                                     if(field.maskedField)
                                        field.maskedField["certificateVerified"] = true;                                   	
                                  }
                              }

                              claims.push({"claim":claim,"verification":sig});
                          }

                          if(claims.length>0){
                            if(false && vouchEntry.vouch.hashedPlainFields)
                                await unmaskFieldVerifications(sig,(await extractClaimPlainFields(vouchEntry.vouch)));

                            validVouchedClaims.push({"entry":vouchEntry,"claims":claims,"isTrustAnchor":isTrustAnchor,"verification":sig})                   
                          }
                    }
                    resolve(validVouchedClaims);
                })
            }
            else
            resolve(validVouchedClaims)
        });
    }

    async function verifyVouches(presentingClaim,docVerificationContext){

        return new Promise(async (resolve,reject)=>{
            presentingClaim  = setPlainFields(presentingClaim);
            //extract and validate embedded vouches
            const vouches = await getValidVouches(presentingClaim,docVerificationContext);

            //treat all trust anchor vouches as trustworthy, essentially as certified certificate fields
            const trustedVouchVerifications = [];
            const untrustedVouches = [];

            for(const vouchEntry of vouches){
                if(vouchEntry.claims.length == 0)
                    continue;

                if(vouchEntry.isTrustAnchor){
                    for(const claimEntry of vouchEntry.claims){
                      trustedVouchVerifications.push(claimEntry.verification);
                    }
                }
                else
                {
                    const vouchVerificationSummary = {"issuer":{},"fields":[],"vouch":vouchEntry,"supportingStatements":[]};

                    //extract issuer information, only allow certificate verified fields as descriptors for the vouch issuer
                    for(const field of vouchEntry.verification.fieldVerification.fields){
                        const rebuiltField = rebuildVerificationField(field);
                        if(!rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                            continue;

                        if(isVerifiedField(vouchEntry.verification,field)){                        
                            vouchVerificationSummary.issuer[rebuiltField.plainField.name] = rebuiltField.plainField.value;
                        }
                        else
                        {
                            vouchVerificationSummary.supportingStatements.push(rebuiltField);
                        }
                    }

                    for(const claimEntry of vouchEntry.claims){
                        const verifiedFields = [];

                        //extract vouched-for information. only include non-certificate fields, those are the ones being vouched for
                        for(const field of claimEntry.verification.fieldVerification.fields){
                            const rebuiltField = rebuildVerificationField(field);
                            if(!rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                                continue;

                            if(!isVerifiedField(claimEntry.verification,field))
                                vouchVerificationSummary.fields.push(rebuildVerificationField(field));
                            else
                                verifiedFields.push(field)
                        }

                        //roll up these verified fields so they are available under verified field section
                        if(verifiedFields.length>0){
                            claimEntry.verification.fieldVerification["preservedFields"]  = claimEntry.verification.fieldVerification.fields;
                            claimEntry.verification.fieldVerification["fields"] = verifiedFields;
                            trustedVouchVerifications.push(claimEntry.verification);
                        }
                    }

                    //don't show as vouch if there are no fields vouched for
                    if(vouchVerificationSummary.fields.length == 0)
                        continue;
                    else
                      untrustedVouches.push(vouchVerificationSummary);
                }

                //remove the unverified field that held this vouch
                for(const field of docVerificationContext.fieldVerification.fields){
                    if(field.plainField.hasOwnProperty(vouchEntry.entry.plainFieldName)){
                        docVerificationContext.fieldVerification.fields.splice(docVerificationContext.fieldVerification.fields.indexOf(field),1);
                        break;
                    }
                }
            }

            //deduplicate display fields
            const knownFields = [];
            for(const rebuiltField of rebuildVerificationFields(docVerificationContext,docVerificationContext.fieldVerification.fields)){
                if(/*!vm.isVerifiedField(field) ||*/ !rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                   continue;

                knownFields.push(rebuiltField);                         
            }

            for(const trustedVouchVerification of trustedVouchVerifications){
                const fields = [];
                fields.push(...trustedVouchVerification.fieldVerification.fields);//supports concurrent modification below

                for(const field of fields){
                     const rebuiltField = rebuildVerificationField(field);
                     if(/*!vm.isVerifiedField(field) ||*/ !rebuiltField.plainField.name || Object.keys(rebuiltField.plainField).length<2)
                        continue;

                     if(knownFields.find(f=>(f.plainField.name && f.plainField.name == rebuiltField.plainField.name && f.plainField.value == rebuiltField.plainField.value)))
                       trustedVouchVerification.fieldVerification.fields.splice(trustedVouchVerification.fieldVerification.fields.indexOf(field),1);
                     else
                       knownFields.push(rebuiltField);
                }
            }

            if(trustedVouchVerifications.length>0)
              Object.assign(docVerificationContext,{"trustedVouchVerifications":trustedVouchVerifications});
            else
              delete docVerificationContext["trustedVouchVerifications"];

            if(untrustedVouches.length>0)
              Object.assign(docVerificationContext,{"untrustedVouches":untrustedVouches});
            else
              delete docVerificationContext["untrustedVouches"];

            resolve();
        });
    }

    function isClaimTrustworthy(docVerificationContext){
      
      	if(!docVerificationContext || !docVerificationContext.certChainVerification)
          return false;

        if(docVerificationContext.isEmbedSticker)
            return (docVerificationContext.certChainVerification.certificateVerified && 
                    !docVerificationContext.failedDHExchangeNonceValidation &&
                    (!docVerificationContext.sigStatusVerification || docVerificationContext.sigStatusVerification == "good") &&
                    docVerificationContext.signatureExpirationStatus !='expired' &&
                    docVerificationContext.signatureExpirationStatus !='invalid' &&
                    docVerificationContext.signatureValidFromStatus !='pretermed' &&
                    docVerificationContext.signatureValidFromStatus !='invalid' &&
                    docVerificationContext.signatureValidFromStatus !='unspecified' &&
                    (!getConfig().clientApp || !getConfig().clientApp.isFlaggedIdentity(docVerificationContext)) && 
                    !docVerificationContext.certChainVerification.chain.find(c=>c.finger_print == getConfig().demoTrustAnchorFingerprint));

        return (docVerificationContext.certChainVerification.certificateVerified && 
                !docVerificationContext.failedDHExchangeNonceValidation &&
                (/*docVerificationContext.certificateIsTrustAnchor ||*//*this.isEmbedSession()*/docVerificationContext.ignoreClaimIdentity || 
                (docVerificationContext.pkiIdentityVerified && 
                docVerificationContext.pkiIdentityReceiverMatch)) &&
                (!docVerificationContext.sigStatusVerification || docVerificationContext.sigStatusVerification == "good") &&
                docVerificationContext.signatureExpirationStatus !='expired' &&
                docVerificationContext.signatureExpirationStatus !='invalid' &&
                docVerificationContext.signatureValidFromStatus !='pretermed' &&
                docVerificationContext.signatureValidFromStatus !='invalid' &&
                docVerificationContext.signatureValidFromStatus !='unspecified' &&
                (!getConfig().clientApp || !getConfig().clientApp.isFlaggedIdentity(docVerificationContext)) && 
                !docVerificationContext.certChainVerification.chain.find(c=>c.finger_print == getConfig().demoTrustAnchorFingerprint));
    }

    /**********************************************************************************************
     *	Author: chatgpt. derived from UI markup structure.													  *
     **********************************************************************************************/
    function getVerificationResult(docVerificationContext,includeInternalFields) {
      if (!docVerificationContext) return null;

      const result = {};

      // Trustworthiness
      const trustworthy = isClaimTrustworthy(docVerificationContext);

      result.trust = {
        isTrustworthy: trustworthy
      };

      if (trustworthy) {
        result.trust.message = "This Claim Is Trustworthy";
        if (docVerificationContext.claimPurpose) {
          result.trust.intendedPurpose = docVerificationContext.claimPurpose;
        }
      } else {
        result.trust.message = "This Claim Is Not Trustworthy";
        result.trust.errors = buildErrorList(docVerificationContext) || [];
      }

      // Verified Information
      const verifiedFieldsRaw = filterVerificationFields(
        docVerificationContext,
        docVerificationContext.fieldVerification.fields,
        true,
        true,
        includeInternalFields
      );

      if (verifiedFieldsRaw && verifiedFieldsRaw.length > 0) {
        result.verifiedInformation = {
          title: "Verified Information",
          fields: []
        };

        const rebuiltVerified = rebuildVerificationFields(
          docVerificationContext,
          docVerificationContext.fieldVerification.fields,
          true,
          true,
          includeInternalFields
        );

        rebuiltVerified.forEach(field => {
          result.verifiedInformation.fields.push({
            name: field.plainField.name,
            value: field.plainField.value
          });
        });

        // Trusted Vouch Verifications
        if (docVerificationContext.trustedVouchVerifications) {
          result.verifiedInformation.trustedVouches = [];

          docVerificationContext.trustedVouchVerifications.forEach(vouchVerification => {
            const rebuiltVouchFields = rebuildVerificationFields(
              vouchVerification,
              vouchVerification.fieldVerification.fields,
              true,
              true,
              includeInternalFields
            );

            const vouchFields = rebuiltVouchFields.map(field => ({
              name: field.plainField.name,
              value: field.plainField.value
            }));

            result.verifiedInformation.trustedVouches.push({
              fields: vouchFields
            });
          });
        }
      }

      // Unverified Information
      const unverifiedFieldsRaw = filterVerificationFields(
        docVerificationContext,
        docVerificationContext.fieldVerification.fields,
        false,
        true,
        includeInternalFields
      );

      if (unverifiedFieldsRaw && unverifiedFieldsRaw.length > 0) {
        result.unverifiedInformation = {
          title: "Unverified Information",
          fields: []
        };

        const rebuiltUnverified = rebuildVerificationFields(
          docVerificationContext,
          docVerificationContext.fieldVerification.fields,
          false,
          true,
          includeInternalFields
        );

        rebuiltUnverified.forEach(field => {
          result.unverifiedInformation.fields.push({
            name: field.plainField.name,
            value: field.plainField.value
          });
        });
      }

      // Owner Identity Information
      if (
        docVerificationContext.pkiIdentityVerified &&
        docVerificationContext["pki-identity"] &&
        docVerificationContext["pki-identity"]["pki-sp-id-anchor-token"]
      ) {
        result.ownerIdentityInformation = {
          id: docVerificationContext["pki-identity"]["pki-sp-id-anchor-token"],
          personaType:
            docVerificationContext["pki-identity"]["pki-sp-id-anchor-token-persona"],
          validForReceiver: docVerificationContext.spUri,
          basedOnIdentityElement:
            docVerificationContext["pki-identity"]["pki-id-anchor-element"]
        };
      }

      // Untrusted Vouches
      if (
        docVerificationContext.untrustedVouches &&
        docVerificationContext.untrustedVouches.length > 0
      ) {
        result.vouching = [];

        docVerificationContext.untrustedVouches.forEach(vouch => {
          const vouchObj = {};

          // Claims Vouched For
          vouchObj.claimsVouchedFor = (vouch.fields || [])
            .filter(field =>
              (field.plainField.name && field.plainField.name.length > 0) ||
              (field.plainField.value && field.plainField.value.length > 0)
            )
            .map(field => ({
              label:
                field.plainField.name && field.plainField.value
                  ? field.plainField.name
                  : "Claim",
              value:
                field.plainField.value && field.plainField.value.length > 0
                  ? field.plainField.value
                  : field.plainField.name
            }));

          // Vouch Issuer
          vouchObj.issuer = Object.keys(vouch.issuer || {}).map(fieldName => ({
            fieldName,
            value: vouch.issuer[fieldName]
          }));

          // Supporting Statements
          if (vouch.supportingStatements && vouch.supportingStatements.length > 0) {
            vouchObj.supportingStatements = vouch.supportingStatements
              .filter(field =>
                (field.plainField.name && field.plainField.name.length > 0) ||
                (field.plainField.value && field.plainField.value.length > 0)
              )
              .map(field => ({
                label:
                  field.plainField.name && field.plainField.value
                    ? field.plainField.name
                    : "Statement",
                value:
                  field.plainField.value && field.plainField.value.length > 0
                    ? field.plainField.value
                    : field.plainField.name
              }));
          }

          result.vouching.push(vouchObj);
        });
      }

      return result;
    }

    function buildErrorList(docVerificationContext){
        
        let messageList = [];  
      
      	if(!docVerificationContext || !docVerificationContext.certChainVerification)
          	return messageList;
      
        if(docVerificationContext.clientErrorList)
            messageList = messageList.concat(docVerificationContext.clientErrorList);

        if(docVerificationContext.certChainVerification.chain.find(c=>c.finger_print == getConfig().demoTrustAnchorFingerprint))
           messageList.push("This claim's certificate was issued using the demo trust anchor certificate!!!");

        if(/*!docVerificationContext.certificateIsTrustAnchor &&*/ /*!docVerificationContext.isEmbedSticker*/ /*!vm.isEmbedSession()*/!docVerificationContext.ignoreClaimIdentity)
        {
            if(!docVerificationContext.pkiIdentityVerified)
            {      
              messageList.push('No valid claimant identity information provided.');
            }

            if(docVerificationContext.pkiIdentityVerified && !docVerificationContext.pkiIdentityReceiverMatch)
            {
               //messageList.push('The receiver for this claim doesn\'t match your receiver Id('+vm.receiverIds+'). It could be a stolen claim.');
               messageList.push(`The claim receiver id for this claim doesn\'t match any of your receiver Ids. It could be a stolen claim.`);
            }    
        }

        if(getConfig().clientApp && getConfig().clientApp.isFlaggedIdentity(docVerificationContext))
        {
            messageList.push(`You are currently tracking this claim creator's identity and you have it flagged!`);

            if(getConfig().clientApp.getTrackedIdentity(docVerificationContext).reason)
              messageList.push(`Your reason for flagging it: ${getConfig().clientApp.getTrackedIdentity(docVerificationContext).reason}`);
        }

        if(!docVerificationContext.certChainVerification.certificateVerified)
        {
          messageList.push('The certificate that attests to this claim was either not issued by a valid Certisfy trust anchor partner (and/or their certificate is invalid) or is not valid (expired,pretermed or revoked).');
        }

        if(docVerificationContext.failedDHExchangeNonceValidation)
        {
           messageList.push('The claim was transmited via a claim exchange but failed validation.');
        }
      
        if(docVerificationContext.signatureExpirationStatus=='unspecified')
        {
          messageList.push(`The claim doesn't specify an expiration time.`);
        } 
        else
        if(docVerificationContext.signatureExpirationStatus=='expired')
        {
          messageList.push('The claim has expired.');
        }
        else
        if(docVerificationContext.signatureExpirationStatus=='invalid')
        {
          messageList.push('The claim has invalid expiration time.');
        }    


        if(docVerificationContext.signatureExpirationStatus !='expired' && docVerificationContext.signatureValidFromStatus=='pretermed')
        {
          messageList.push('The claim is for a future date.');
        }
        else
        if(docVerificationContext.signatureValidFromStatus=='invalid')
        {
          messageList.push('The claim has invalid future validity time.');
        }  

        if(docVerificationContext.sigStatusVerification && docVerificationContext.sigStatusVerification != "good"){
          messageList.push(`The claim's status(${docVerificationContext.sigStatusVerification}) is invalid.`);    
        }

        return messageList;
    }

    function isVerifiedField(docVerificationContext,field){
       return ((docVerificationContext.certChainVerification.certificateVerified) && (field.plainField.certificateVerified && (typeof field.maskedField == 'undefined' || field.maskedField.certificateVerified)));      
    }

    function rebuildVerificationField(field,includeInternalFields){
           let metaPlainField = {};
           for(let key in field.plainField)
           {
               if((!includeInternalFields || !includeInternalFields.includes(key)) && isInternalFieldName(key))
                 metaPlainField[key] = field.plainField[key];
               else
               {
                 metaPlainField['name'] = key; 
                 metaPlainField['value'] = field.plainField[key]; 
               }
           }

           let metaMaskedField = {};
           for(let key in field.maskedField)
           {
               if((!includeInternalFields || !includeInternalFields.includes(key)) && isInternalFieldName(key))
                 metaMaskedField[key] = field.maskedField[key];
               else
               {
                 metaMaskedField['name'] = key; 
                 metaMaskedField['value'] = field.maskedField[key]; 
               }
           }
           let metaField = Object.assign({},{"plainField":metaPlainField,"maskedField":metaMaskedField});
           return metaField;
    }

    function filterVerificationFields(docVerificationContext,fields,verified,hideInternal,includeInternalFields){
        const resultSet = [];
        for(var i=0;i<fields.length;i++)
        {
            var field = fields[i];            
          
            if((!includeInternalFields || !includeInternalFields.includes(Object.keys(field.plainField)[0])) && hideInternal && isInternalField(field))
              continue;

            if(verified && isVerifiedField(docVerificationContext,field))
            {
               resultSet.push(field);
            }
            else
            if(!verified && !isVerifiedField(docVerificationContext,field))
            {
               resultSet.push(field);
            }
        }
        //console.log("filterVerificationFields:"+verified);
        //console.log(resultSet);

        return resultSet;
    }

    function rebuildVerificationFields(docVerificationContext,fields,verificationFilter,internalFieldFilter,includeInternalFields){    
        let filteredFields = fields;
        if(typeof verificationFilter != "undefined")
          filteredFields = filterVerificationFields(docVerificationContext,fields,verificationFilter,internalFieldFilter,includeInternalFields);

        let metaFields = [];
        for(let i=0;i<filteredFields.length;i++)
        {
           let field = filteredFields[i];      
           metaFields.push(rebuildVerificationField(field,includeInternalFields));       
        }
        //console.log("metaFields",metaFields)
        return metaFields;
    }

    function getVerificationField(docVerificationContext,fieldName){
        let metaFields = rebuildVerificationFields(docVerificationContext,docVerificationContext.fieldVerification.fields);
        for(let i=0;i<metaFields.length;i++)
        {
          if(metaFields[i].plainField.name && metaFields[i].plainField.name == fieldName)
            return metaFields[i];

          if(metaFields[i].plainField[fieldName])//meta data
            return metaFields[i];      
        }
        return null;
    }

    async function verifyText(signedString,signature,signerCert){

            //console.log(signerCert,decodeCertificate(signerCert))
            const parsedKey = decodeCertificate(signerCert).subjectPublicKeyInfo.parsedKey;
            //const publicKeyExtract = pkijs.PublicKeyInfo.fromBER(decodeCertificate(signerCert).subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
      		//console.log(parsedKey);
      		//console.log(toPEM(parsedKey.toSchema().toBER(false),"PUBLIC KEY"))
            let signerPublicKey =  await crypto.subtle.importKey(
                  //"spki", // Key format
                  //decodeCertificate(signerCert).subjectPublicKeyInfo,
                  //"pkcs8",
                  //fromPEM(toPEM(parsedKey.toSchema().toBER(false),"PUBLIC KEY")),
                  "raw",
                   parsedKey.toSchema().toBER(false),
                  (parsedKey.namedCurve?{
                    name:getConfig().signAlg,
                    hash:getConfig().hashAlg,
                    namedCurve:parsedKey.namedCurve
                  }:{
                    name:getConfig().signAlg,
                    hash:getConfig().hashAlg
                  }), // Algorithm details (modify for your encryption algorithm)
                  true, // Whether the key is extractable
                  ["verify"] // Key usages
            );
      
        //console.log(signerPublicKey)

        let signedStringHash = await sha2Hex(signedString);
      
        let result = await crypto.subtle.verify(
            (parsedKey.namedCurve?{
                    name:getConfig().signAlg,
                    hash:getConfig().hashAlg,
                    namedCurve:parsedKey.namedCurve
                  }:{name:getConfig().signAlg,hash:getConfig().hashAlg}),
            signerPublicKey,
            base64DecodeToBin(signature),
            new TextEncoder().encode(signedStringHash),
        );

        return result;
    }


	function configure(_sdk){
        sdk = _sdk;

      	certStore.configure(sdk);
        certisfyAPI.configure(sdk);
      	claimData.configure(sdk);
    }

	export  {
      verifyText,
      verifyClaim,
      verifyDHExchangeClaim,
      isClaimTrustworthy,
      buildErrorList,
      verifyVouches,
      isValidDHExchange,
      isVerifiedField,
      isTrustAnchor,
      isTrustAnchorCert,
      getVerificationResult,
      getVerifiedCertificateField,
      filterVerificationFields,
      rebuildVerificationFields,
      rebuildVerificationField,
      getVerificationField,
      certField,
      isIdentityCert,
      initiateDHExchange,
      configure
    };