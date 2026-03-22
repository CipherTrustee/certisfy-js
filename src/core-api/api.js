
	//module configurable
	let sendRequest;

    async function postCSR(params){
      	return new Promise((resolve,reject)=>{
			sendRequest(Object.assign({"pki_action":"post-csr"},params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function getCSR(csr_id){
      	return new Promise((resolve,reject)=>{          
			sendRequest({
              "pki_action":"get-csr",
              "csr_id":csr_id
            }).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function deleteCSR(csr_id){
      	return new Promise((resolve,reject)=>{          
			sendRequest({
              "pki_action":"delete-csr",
              "csr_id":csr_id
            }).
            then(function(resp){
                resolve(resp);
            })
        });      
    }


    async function postCert(params){
      	return new Promise((resolve,reject)=>{
			sendRequest(Object.assign({"pki_action":"post-cert"},params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function getCert(params){
      	return new Promise((resolve,reject)=>{          
			sendRequest(Object.assign({
              "pki_action":"get-cert"
            },params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function deleteCert(params){
      	return new Promise((resolve,reject)=>{          
			sendRequest(Object.assign({
              "pki_action":"delete-cert"
            },params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }


    async function getCertChain(params){
      	return new Promise((resolve,reject)=>{          
			sendRequest(Object.assign({
              "pki_action":"get-cert-chain"
            },params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function postCertIdentity(params){
      	return new Promise((resolve,reject)=>{          
			sendRequest(Object.assign({
              "pki_action":"post-cert-identity"
            },params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function postDHExchange(params){
        return new Promise((resolve,reject)=>{
          	sendRequest(Object.assign({"trp_action":"post-dh-exchange"},params)).
            then(function(resp){
				resolve(resp);
            });
        });
    }

    async function getDHExchange(userCode){
        return new Promise((resolve,reject)=>{
          	sendRequest({
              "user_code":userCode,
              "trp_action":"get-dh-exchange"
            }).
            then(function(resp){
				resolve(resp);
            });
        });
    }

    async function deleteDHExchange(userCode){
        return new Promise((resolve,reject)=>{
          	sendRequest(Object.assign({"trp_action":"delete-dh-exchange","user_code":userCode},{})).
            then(function(resp){
				resolve(resp);
            });
        });
    }


    async function postSignature(params){
      	return new Promise((resolve,reject)=>{
			sendRequest(Object.assign({"pki_action":"post-signature"},params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function updateSignature(signer_signature){
      	return new Promise((resolve,reject)=>{          
			sendRequest({
              "pki_action":"update-signature",
              "signer_signature":signer_signature
            }).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function getSignature(sig_id){
      	return new Promise((resolve,reject)=>{          
			sendRequest({
              "pki_action":"get-signature",
              "sig_id":sig_id
            }).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function deleteSignature(signer_signature){
      	return new Promise((resolve,reject)=>{          
			sendRequest({
              "pki_action":"delete-signature",
              "signer_signature":signer_signature
            }).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

    async function postVerify(params){
      	return new Promise((resolve,reject)=>{          
			sendRequest(Object.assign({
              "pki_action":"post-verify"
            },params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }


    async function postServiceRequest(params){
      	return new Promise((resolve,reject)=>{          
			sendRequest(Object.assign({
              "pki_action":"post-service-request"
            },params)).
            then(function(resp){
                resolve(resp);
            })
        });      
    }

	function configure(sdk){
    	sendRequest = sdk.sendRequest;
    }

	export  {
      postCSR,
      getCSR,
      deleteCSR,

      postCert,
      getCert,
      deleteCert,      
      
      postDHExchange,
      getDHExchange,
      deleteDHExchange,
      
      postSignature,
      updateSignature,
      deleteSignature,
      getSignature,
      
      getCertChain,
  	  postCertIdentity,
      postVerify,
      postServiceRequest,
      
      configure
    };