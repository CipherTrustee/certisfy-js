    import * as certisfyAPI from '../core-api/api.js';
	import * as helperUtil from '../utils/helpers.js';
	import * as certUtil from '../utils/cert.js';

	import * as defaultConfig from '../config.js';

	const {decodeCertificate,getCertificatePayload,certPayloadHasField,getCertIssuerFingerPrint,exportCertificate} = certUtil;
	const {getCertChain} = certisfyAPI;
	const {copyFromObject} = helperUtil;

	let sdk;

	function getConfig(){
    	return sdk?sdk.getConfig():defaultConfig;
    }

    async function getCertFromStore(finger_print){
      
      return new Promise((resolve,reject)=>{
          if(getConfig().clientApp && getConfig().clientApp.findCertificate(finger_print)){
               getLocalCert(finger_print).then((cert)=>resolve(cert.certEntry));
          }
          else
          {
              getCertChainFromStore(finger_print).then((chain)=>resolve(chain.certs.length>0?chain.certs[0]:null));
          }
      });    
    }

	async function getCertChainWithStatusFromStore(trustChain){
        if(!getConfig().apiInfo.target)
               return trustChain;
      
        let chainFingerPrints = [];
        for(let i=0;i<trustChain.length;i++)
          chainFingerPrints.push(trustChain[i].finger_print);
      	
        let chainStatus = await getCertChainFromStore(null,chainFingerPrints.join(","));
      
      	let _trustChain = [];
        for(let i=0;i<chainStatus.length;i++){
            let cert = JSON.parse(JSON.stringify(trustChain[i]));
            _trustChain.push(cert);
          
            if(chainStatus[i].notRegistered)
              continue;
          	
            cert.status =  chainStatus[i].status;
            cert.status_message =  chainStatus[i].status_message;
            cert.revocation_date =  chainStatus[i].revocation_date;

            cert.authority_status =  chainStatus[i].authority_status;
            cert.authority_status_message =  chainStatus[i].authority_status_message;
            cert.authority_suspension_date =  chainStatus[i].authority_suspension_date;
          
          	if(chainStatus[i].hasOwnProperty("isTrustworthy"))
              cert.isTrustworthy =  chainStatus[i].isTrustworthy;
          
            if(chainStatus[i].hasOwnProperty("issuer_finger_print"))
              cert.issuer_finger_print =  chainStatus[i].issuer_finger_print;
          
            if(chainStatus[i].hasOwnProperty("derivation_source_finger_print"))
              cert.derivation_source_finger_print =  chainStatus[i].derivation_source_finger_print;
          
          	if(chainStatus[i].hasOwnProperty("derivation_source_issuer_finger_print"))
              cert.derivation_source_issuer_finger_print =  chainStatus[i].derivation_source_issuer_finger_print;
        }
      	return _trustChain;
    }

    async function getCertChainFromStore(finger_print,chain_health_check,ignoreIssuerPrivacy=true,ignoreDerivationSourcePrivacy=true,ignoreDerivationSourceIssuerPrivacy=true,ignoreLocalStore=false){
      	return new Promise((resolve,reject)=>{
          
            if(!getConfig().apiInfo.target)
               return resolve(chain_health_check?[]:{"certs":[]})
          
          
          	let args = chain_health_check?{
                    	"pki_action":"get-cert-chain",
                      	"chain_health_check":chain_health_check
                    }:{
                      "pki_action":"get-cert-chain",
                      "fingerprint":finger_print
            };
          
			getCertChain(args).
            then(function(resp){
              
                if(resp.status && resp.status != "failure"){
                	resolve(resp.chain);
                }
                else
                if(!ignoreLocalStore && getConfig().clientApp && getConfig().clientApp.findCertificate(finger_print))
                {
                  	getCertChainFromLocalStore(finger_print,chain_health_check,ignoreIssuerPrivacy,ignoreDerivationSourcePrivacy,ignoreDerivationSourceIssuerPrivacy).then((chain)=>{
                    	resolve(chain)
                    })
                    //exportCertificate(getConfig().clientApp.findCertificate(finger_print).cert_text).then((cert)=>resolve({"certs":[Object.assign(cert,{"fromLocalStore":true})]}));
                }
                else
                {
                 	resolve({"certs":[]}); 
                }
            })
        });
    }

	async function getLocalCert(finger_print){
        if(getConfig().clientApp){
            let certEntry = getConfig().clientApp.findCertificate(finger_print);
            let certExport = await exportCertificate(certEntry.cert_text,Object.assign({"fromLocalStore":true},copyFromObject(certEntry,["issuer_finger_print","derivation_source_finger_print","derivation_source_issuer_finger_print"])))
            return {certExport,certEntry};
        }
    }

	function isLocalCert(finger_print){
        return (getConfig().clientApp && getConfig().clientApp.findCertificate(finger_print));
    }

	async function getCertChainFromLocalStore(finger_print,chain_health_check,ignoreIssuerPrivacy,ignoreDerivationSourcePrivacy,ignoreDerivationSourceIssuerPrivacy){
          //attempt to resolve chain, always prioritize registry lookup over 
          //local store or attached trust chains

          const certs = [];
          let cert = await getLocalCert(finger_print);
          certs.push(cert.certExport);

          const issuer = await getCertIssuerFingerPrint(cert.certExport);                        
          if(issuer != "Prometheus")
            certs.push(... (await getCertChainFromStore(issuer,chain_health_check,(ignoreIssuerPrivacy || !cert.certEntry.isUsingPrivateIssuer),(ignoreDerivationSourcePrivacy || !cert.certEntry.isUsingPrivateDerivedFromSource),(ignoreDerivationSourceIssuerPrivacy || !cert.certEntry.isUsingPrivateDerivedFromSourceIssuer))).certs);

      	  if(!ignoreIssuerPrivacy && cert.certEntry.isUsingPrivateIssuer)
            delete cert.certExport["issuer_finger_print"];
      
      	  if(!ignoreDerivationSourcePrivacy && cert.certEntry.isUsingPrivateDerivedFromSource)
            delete cert.certExport["derivation_source_finger_print"];
      
          if(!ignoreDerivationSourceIssuerPrivacy && cert.certEntry.isUsingPrivateDerivedFromSourceIssuer)
            delete cert.certExport["derivation_source_issuer_finger_print"];
      
          return {"certs":certs};
    }

	function configure(_sdk){
    	sdk = _sdk;      
        certisfyAPI.configure(sdk); 	
    }

	export {
    	getCertFromStore,
      	getCertChainWithStatusFromStore,
      	getCertChainFromStore,
      	getLocalCert,
      	isLocalCert,
      	getCertChainFromLocalStore,
        configure
	}