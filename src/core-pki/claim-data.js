    import * as cryptoUtil from '../utils/crypto.js';
    import * as helperUtil from '../utils/helpers.js';
    import * as certUtil from '../utils/cert.js';

	import * as defaultConfig from '../config.js';

	const {isValidString,textToClaimObject} = helperUtil;
	const {sha2Hex,hmacHex} = cryptoUtil;
	const {decodeCertificate,getCertificatePayload} = certUtil;

	//access to properly configured modules
    let sdk;

	function getConfig(){
    	return sdk?sdk.getConfig():defaultConfig;
    }

    function isInternalField(field){
           for(let key in field.plainField)//assume just one entry
           {
               if(key != "certificateVerified" &&
                  key != "certificateVerificationFailure" &&
                  !key.startsWith('certisfy-') &&
                  !key.startsWith('pki-')/* &&
                  !isIDElementHash(key)*/)
                 return false;
           }
           return true;
    }

    function isInternalFieldName(key){
        if(key != "certificateVerified" &&
                   key != "certificateVerificationFailure" &&
                   !key.startsWith('certisfy-') && 
                   !key.startsWith('pki-') /*&&
                   !isIDElementHash(key)*/)
                  return false;
                 return true;
    }

    function getVerifiedCertificateField(fieldName,fields,sigVerified=false){
      //exec.logger().info("fieldName:"+fieldName+","+fields.size());
        for(let i =0;i<fields.length;i++){
            let field = fields[i];
            //exec.logger().info(field);
            if(Object.hasOwn(field.plainField, fieldName)){
              if(field.plainField.certificateVerified || sigVerified)
              	return field.plainField;
              else
              	return null;
            }
        }
      	return null;
    }
  
    function hasClaimField(fieldName,fields){
      //exec.logger().info("fieldName:"+fieldName+","+fields.size());
        for(let i =0;i<fields.length;i++){
            let field = fields[i];
            //exec.logger().info(field);
            if(Object.hasOwn(field.plainField?field.plainField:field, fieldName)){
               return true;
            }
        }
      	return false;
    }  

    async function getMatchingMaskedFields(plainFields,maskedFields,hmacKeyMask){
      
        let matchedMaskedFields = [];
        for(const plainField of plainFields){
            let fieldName    = Object.keys(plainField)[0];
            let fieldValue 	 = plainField[fieldName];

            //let fieldNameHash = await sha2Hex(fieldName);
            //let fieldValueHash = fieldValue?(await sha2Hex(fieldValue)):fieldValue;
      		let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(plainField,getConfig().PUBLIC_PLAIN_FIELDS);

          
          	let matched = false;
            for(const maskedField of maskedFields){
              	  if(!maskedField.hmacKey)
                    	continue;
              
                  let hmacKey = hmacKeyMask?hmacKeyMask[maskedField.hmacKey]:maskedField.hmacKey;
              
                  if((maskedField[hmacHex(hmacKey,fieldName)] == hmacHex(hmacKey,fieldValue))
                    ||
                     (maskedField[hmacHex(hmacKey,fieldNameHash)] == hmacHex(hmacKey,fieldValueHash))
                    ){
                     matchedMaskedFields.push(maskedField);
                     matched = true;
                     break;
                  }
            }
          	if(!matched)
              	return;
        }
      
        if(matchedMaskedFields.length>0)
          	return matchedMaskedFields;
    }

	async function unmaskFieldVerifications(context,plainFields){
        for(const plainField of plainFields){
             let fieldName    = Object.keys(plainField)[0];
             let fieldValue 	 = plainField[fieldName];

             let fieldNameHash = await sha2Hex(fieldName);
             let fieldValueHash = fieldValue?(await sha2Hex(fieldValue)):fieldValue; 
          
          	 let hashedPlainField = context.fieldVerification.fields.find(f=>(f.plainField.hasOwnProperty(fieldNameHash) && f.plainField[fieldNameHash] == fieldValueHash));
          	 if(hashedPlainField){
             	hashedPlainField.plainField[fieldName] = fieldValue;
                delete hashedPlainField.plainField[fieldNameHash];
             }
        }
    }

	function filterFields(fields,filter){
        let filteredFields = [];
        for(let i=0;i<filter.length;i++){
            for(let j=0;j<fields.length;j++){
                if(fields[j][filter[i]]){
                    filteredFields.push(fields[j]);
                    break;
                }
            }
        }
        return filteredFields;
    }

	async function maskClaimPlainFields(plainFields,textPlainFields = [],skipTextFields=false){
        if(plainFields){
            const claimPlainFields = [];
          
            for(const plainField of plainFields){
                const plainFieldName = Object.keys(plainField)[0]
              	const claim = textToClaimObject(plainField[plainFieldName]);

                if(claim && claim.plainFields && Array.isArray(claim.plainFields)){
                    claim.plainFields = await maskClaimPlainFields(claim.plainFields,textPlainFields);
                    let usePlainFieldName = !plainFieldName.startsWith("pki-")?(await sha2Hex(plainFieldName)):plainFieldName;

                	claimPlainFields.push({[usePlainFieldName]:JSON.stringify(claim)});
                }
              	else
                if(!skipTextFields)
                {
                    if(!["pki-valid-from-time","pki-expiration-time"].includes(plainFieldName))
                      claimPlainFields.push({[(await sha2Hex(plainFieldName))]:(await sha2Hex(plainField[plainFieldName]))});
                    else
                      claimPlainFields.push({[plainFieldName]:plainField[plainFieldName]});                	
                }
                textPlainFields.push(plainField);
            }
            return claimPlainFields;
        }
    }

    async function getVouches(plainFields,plainFieldsSummary){

        return new Promise(async (resolve,reject)=>{
        let vouches = [];
        for(const plainField of plainFields){

            const plainFieldName = Object.keys(plainField)[0];
            const plainFieldVal = plainField[plainFieldName];

            if(plainFieldName != "pki-claim-vouch")
              continue;

            let vouchClaim = textToClaimObject(plainFieldVal);
            //console.log("checking vouch claim plain fields:"+plainFieldName);
            if(vouchClaim){
                try
                {
                    let plainFieldHashName = "pki-plain-fields:"+(await sha2Hex(/*plainFieldVal*/vouchClaim.signature));
					vouchClaim = setPlainFields(vouchClaim);//ensure there is an appropriate plainFields object
                  
                    //restore any plain fields from containing claim object plainFields for contained claim
                    if(plainFields.find(f=>f[plainFieldHashName]))
                        vouchClaim.plainFields = JSON.parse(plainFields.find(f=>f[plainFieldHashName])[plainFieldHashName]);
                  
                    //console.log("extracting vouch claim plain fields",vouchClaim,plainFieldHashName,plainFields);
                    if(vouchClaim.plainFields && Array.isArray(vouchClaim.plainFields)){

                        const claims = [];
                        const supportingStatements = [];

                        for(const embeddedPlainField of vouchClaim.plainFields){
                            const embeddedPlainFieldName = Object.keys(embeddedPlainField)[0];
                            const embeddedPlainFieldVal  = embeddedPlainField[embeddedPlainFieldName];
                            //console.log("checking vouched for claim plain fields",embeddedPlainFieldName)
                            if((embeddedPlainFieldName.startsWith("pki-vouch-for-claim") || embeddedPlainFieldName == "pki-vouch-claim")  && embeddedPlainFieldVal){
                                try
                                {
                                    let claim = JSON.parse(embeddedPlainFieldVal);
                                    claim = setPlainFields(claim);//ensure there is an appropriate plainFields object

                                    let plainFieldHashName = "pki-plain-fields:"+(await sha2Hex(/*embeddedPlainFieldVal*/claim.signature));
                                  
                                    //restore any plain fields from containing claim object plainFields for contained claim
                                    if(vouchClaim.plainFields.find(f=>f[plainFieldHashName]))
                                        claim.plainFields = JSON.parse(vouchClaim.plainFields.find(f=>f[plainFieldHashName])[plainFieldHashName]);

                                    //console.log("extracting vouched for claim plain fields",claim,plainFieldHashName);
                                    claims.push(claim);
                                }
                                catch(error){}
                            }
                            else
                            supportingStatements.push(embeddedPlainField)
                        }

                        if(claims.length>0)
                          vouches.push({"vouch":vouchClaim,"plainFieldName":plainFieldName,"claims":claims,"supportingStatements":supportingStatements});
                    }
                }
                catch(error){
                    console.warn(`Error extracting vouched for claims`,error)
                }
            }
        }

        resolve(vouches);
        });
    }

	function fieldsContainVouchedForClaims(plainFields){
      
      	if(!plainFields)
          	return false;
      
        for(let plainField of  plainFields){
            const plainFieldName = Object.keys(plainField)[0];

            //this means claim is a vouch claim
            if(plainFieldName.startsWith("pki-vouch-for-claim") && textToClaimObject(plainField[plainFieldName]))
              	return true;
        }
    }

	function claimContainsVouchedForClaims(presentingClaim){
      
      	if(!presentingClaim.plainFields)
          	return false;
      
        for(let plainField of presentingClaim.plainFields){
            const vouchClaim = textToClaimObject(plainField[Object.keys(plainField)[0]]);

            if(vouchClaim && fieldsContainVouchedForClaims(vouchClaim.plainField))
                return true;            
        }
    }

    function filterPlainFields(plainFields,filter){
        if(plainFields.find(f=>f["pki-hmac-keys"])){
            let hmacKeys = JSON.parse(plainFields.find(f=>f["pki-hmac-keys"])["pki-hmac-keys"]);

            let filteredHMACKeys = []          
            let filteredFields = [];
          
            for(let i=0;i<filter.length;i++){
                for(let j=0;j<plainFields.length;j++){
                    if(plainFields[j][filter[i]]){
                        filteredFields.push(plainFields[j]);
                        filteredHMACKeys.push(hmacKeys[j])
                        break;
                    }
                }
            }            
          
            //last entry represents the pki-hmac-keys field's hmac key
            filteredHMACKeys.push(hmacKeys[hmacKeys.length-1]);
            filteredFields.push({"pki-hmac-keys":JSON.stringify(filteredHMACKeys)})
          
            return filteredFields;
        }
      
        return filterFields(plainFields,filter);
    }

	function getFlatPlainFields(plainFields){
		let flatField = {};
        for(const plainField of plainFields){
			if(plainField.hasOwnProperty("name") && plainField.hasOwnProperty("value"))
          		flatField[plainField.name] = plainField.value;
          	else
              	flatField[Object.keys(plainField)[0]] = plainField[Object.keys(plainField)[0]];
        }
        return flatField;
    }

	async function hashPlainField(plainField,excludeFields=[],includeFields=[],excludeInternalFields=false,hmacKey,skipHash){
        const hashedPlainField 	= await getHashedPlainField(plainField,excludeFields,includeFields,excludeInternalFields,hmacKey,skipHash);
        let fieldName    	= Object.keys(hashedPlainField)[0];
        let fieldValue 	 	= hashedPlainField[fieldName];
      	return {fieldName,fieldValue};
    }

	async function getHashedPlainField(plainField,excludeFields=[],includeFields=[],excludeInternalFields=false,hmacKey,skipHash){
          
        let fieldName    = Object.keys(plainField)[0];
        let fieldValue 	 = plainField[fieldName];

        if(excludeFields && excludeFields.includes(fieldName))
          return plainField;

        if((excludeInternalFields && (fieldName.startsWith("pki-") || fieldName.startsWith("certisfy-"))) && (!includeFields || !includeFields.includes(fieldName)))
          return;
      	
      	let hashName 		= await sha2Hex(fieldName);
        let useName 		= skipHash?fieldName:hashName;
      
        let hashValue 		= isValidString(fieldValue)?(await sha2Hex(fieldValue)):fieldValue;
        let useValue 		= skipHash?fieldValue:hashValue;
      
        let fieldNameHash 	= (hmacKey && hmacKey.length>0)?hmacHex(hmacKey,useName):useName;
        let fieldValueHash  = (hmacKey && hmacKey.length>0) && isValidString(useValue)?hmacHex(hmacKey,useValue):useValue;      
      
        if(fieldName == "pki-hmac-keys"){//don't sha2 hmac keys
            if(hmacKey && hmacKey.length>0)
            	return {[hmacHex(hmacKey,"pki-hmac-keys")]:hmacHex(hmacKey,fieldValue)};
          
            return plainField;
        }
        else
        if(fieldName.startsWith("pki-plain-fields:")){//preserve structure while hashing
          	let hmacKeys;
          	let extractedPlainFields = JSON.parse(fieldValue);
          	if(hmacKey && extractedPlainFields.find(f=>f["pki-hmac-keys"])){
            	hmacKeys = extractedPlainFields.find(f=>f["pki-hmac-keys"])
                //extractedPlainFields.splice(1,extractedPlainFields.indexOf(hmacKeys));
              	hmacKeys = JSON.parse(hmacKeys["pki-hmac-keys"]);
            }
          
          	return {[fieldName]: JSON.stringify(await getHashedPlainFields(extractedPlainFields,getConfig().PUBLIC_PLAIN_FIELDS,null,false,hmacKeys,skipHash)) };
        }
        else
        {            
            return {[fieldNameHash]:fieldValueHash};
        }
    }

    async function getHashedPlainFields(plainFields,excludeFields=[],includeFields=[],excludeInternalFields=false,hmacKeys,skipHash){
      
          let hashedPlainFields = [];
          for(let i=0;i<plainFields.length;i++){
              const plainField = plainFields[i];
            
              const hashedPlainField = await getHashedPlainField(plainField,excludeFields,includeFields,excludeInternalFields,(hmacKeys?hmacKeys[i]:null),skipHash);
              if(hashedPlainField)
                	hashedPlainFields.push(hashedPlainField);
          }
          return hashedPlainFields;
    }

	async function getUnHashedPlainField(hashPlainFields,plainField,hmacKey,skipHash){

        let fieldName = (plainField.name && Object.keys(plainField).length>1) ?plainField.name:Object.keys(plainField)[0];
        let fieldValue = (plainField.name && Object.keys(plainField).length>1)?plainField.value:plainField[fieldName];              

      	/*
      	let hashName 		= await sha2Hex(fieldName);
        let useName 		= skipHash?fieldName:hashName;
      
        let fieldNameHash 	= hmacKey?hmacHex(hmacKey,useName):useName;
        */
      	let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(plainField,getConfig().PUBLIC_PLAIN_FIELDS,null,false,hmacKey,skipHash);      
      
        if(fieldName.startsWith("pki-plain-fields:") && hashPlainFields.find(h=>(h.hasOwnProperty(fieldName)))){
          	let hmacKeys;
          	let extractedPlainFields = JSON.parse(fieldValue);
          	if(hmacKey && extractedPlainFields.find(f=>f["pki-hmac-keys"])){
            	hmacKeys = extractedPlainFields.find(f=>f["pki-hmac-keys"])
                //extractedPlainFields.splice(1,extractedPlainFields.indexOf(hmacKeys));
              	hmacKeys = JSON.parse(hmacKeys["pki-hmac-keys"]);
            }

          	return {[fieldName]: JSON.stringify(await getUnHashedPlainFields(JSON.parse(hashPlainFields.find(h=>(h.hasOwnProperty(fieldName)))[fieldName]),extractedPlainFields,hmacKeys,skipHash)) };
        }
        else
        {
          	/*
            let hashValue = fieldValue?(await sha2Hex(fieldValue)):fieldValue;
          	let useValue =  skipHash?fieldValue:hashValue;
            
            let fieldValueHash = hmacKey && useValue?hmacHex(hmacKey,useValue):useValue;
            */
            
            if(!hashPlainFields.find(h=>(h.hasOwnProperty(fieldNameHash) && h[fieldNameHash] == fieldValueHash)) &&
               !hashPlainFields.find(h=>(h.hasOwnProperty(fieldName) && h[fieldName] == fieldValue)) &&
               !hashPlainFields.find(h=>(h.hasOwnProperty(fieldNameHash) && h[fieldNameHash] == fieldValue)))
              return;

            return {[fieldName]:fieldValue};
        }
    }

	async function getUnHashedPlainFields(hashPlainFields,plainFields,hmacKeys,skipHash,ifPlainFieldEmptyReturnHashed=false){
      	  if(!plainFields || plainFields.length == 0){
              if(ifPlainFieldEmptyReturnHashed)
      			 return hashPlainFields;

              return [];
      	  }      

          let unHashedPlainFields = [];
          for(let i=0;i<plainFields.length;i++){
              const plainField = plainFields[i];

              const unHashedPlainField = await getUnHashedPlainField(hashPlainFields,plainField,(hmacKeys?hmacKeys[i]:null),skipHash);
              if(unHashedPlainField)
                	unHashedPlainFields.push(unHashedPlainField);
          }

          return unHashedPlainFields;    
    }

	async function extractClaimPlainFields(claim,verification,strict=false){
        let signedStringObject = JSON.parse(claim.signedString.substring(0,claim.signedString.lastIndexOf("}")+1));
        let plainFields = claim.plainFields?claim.plainFields:signedStringObject.plainFields;
        if(!plainFields)
          	plainFields = [];
      
		let usePlainField = [];
        usePlainField.push(...plainFields);
      
        /*
        let hashedPlainFields = claim.hmacedPlainFields;
        if(!hashedPlainFields)
      		hashedPlainFields = claim.hashedPlainFields; 
      
        
        //console.log("usePlainField1",usePlainField)
        usePlainField = hashedPlainFields?(await getUnHashedPlainFields(hashedPlainFields,usePlainField)):usePlainField;
        //console.log("usePlainField2",usePlainField)
      
      	if(!strict && usePlainField.length == 0 && hashedPlainFields)
          	usePlainField.push(...hashedPlainFields)
        */
      
        if(!verification)
          return usePlainField;
      
     	let verifiedPlainFields = [];
        for(const plainField of usePlainField){
            let fieldName    = Object.keys(plainField)[0];
            let fieldValue 	 = plainField[fieldName];

            //let fieldNameHash = await sha2Hex(fieldName);
            //let fieldValueHash = fieldValue?(await sha2Hex(fieldValue)):fieldValue; 

          	/*
          	let {fieldName:fieldNameHash,fieldValue:fieldValueHash} = await hashPlainField(plainField,getConfig().PUBLIC_PLAIN_FIELDS);

            let verifiedField = verification.fieldVerification.fields.find(f=>((f.plainField.hasOwnProperty(fieldName) || f.plainField.hasOwnProperty(fieldNameHash)) && (f.plainField[fieldName] == fieldValue || f.plainField[fieldNameHash] == fieldValueHash)));
            if(verifiedField)
              verifiedPlainFields.push(plainField);
            */
          
            let verifiedField = verification.fieldVerification.fields.find(f=>((f.plainField.hasOwnProperty(fieldName)) && (f.plainField[fieldName] == fieldValue)));
            if(verifiedField)
              verifiedPlainFields.push(plainField);
        }
        return verifiedPlainFields;
    }


	function publicPlainFields(signature){
      
    	if(signature.plainFields)
          	return signature.plainFields;
      
    	if(signature.hashedPlainFields)
          	return signature.hashedPlainFields;
      
    	if(signature.hmacedPlainFields)
          	return signature.hmacedPlainFields;
    }
  
	function privatePlainFields(signature){
    	if(signature.hmacedPlainFields)
          	return signature.hmacedPlainFields;
    
    	if(signature.hashedPlainFields)
          	return signature.hashedPlainFields;
      
    	if(signature.plainFields)
          	return signature.plainFields;
      
      	return null;
    }

	function setPlainFields(signature,asPublic=true){
        const claim = JSON.parse(JSON.stringify(signature));//clone
      
      	delete claim["hashedPlainFields"];
      	delete claim["hmacedPlainFields"];
      
      	if(asPublic && publicPlainFields(signature))
      		claim["plainFields"] = publicPlainFields(signature);
      	else
      	if(!asPublic && privatePlainFields(signature))
      		claim["plainFields"] = privatePlainFields(signature);
      
      	return claim;
    }

	function configure(_sdk){
    	sdk = _sdk;
    }

	export  {
      filterFields,
      getMatchingMaskedFields,
      hashPlainField,
      getHashedPlainFields,
      getUnHashedPlainFields,
      getHashedPlainField,
      getUnHashedPlainField,
      extractClaimPlainFields,
      unmaskFieldVerifications,
      maskClaimPlainFields,
	  filterPlainFields,
      hasClaimField,
      claimContainsVouchedForClaims,
      fieldsContainVouchedForClaims,
      getVouches,
      getVerifiedCertificateField,
      setPlainFields,
      isInternalFieldName,
      isInternalField,
      configure,
    };