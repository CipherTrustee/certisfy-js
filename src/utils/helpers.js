
	function isValidString(str){
    	return !(typeof str == "undefined" || str == null)
    }

	function copyFromObject(src,fields){
    	const resp = {};
      	for(const field of fields){
        	if(src[field])
              	resp[field] = src[field];
        }
      	return resp;
    }

    function formatTo2Digits(n){
        return n<9?"0"+n:n;
    }

	function textToClaimObject(text){
		if(text && text.trim().startsWith("{") && text.trim().endsWith("}")){
            try
            {
              const obj = JSON.parse(text);
              if(obj.certisfy_object && obj.signerID)
                	return obj;
            }
            catch(error){
            }
        }    
    }

	function createClaimDateTime(claimDate,claimTime,defaultTime){
      	if(claimDate && claimDate.length>0){
            let localDateTime = new Date();
            let validfromDateTime = claimDate;                  
            localDateTime.setFullYear(parseInt(validfromDateTime.split("/")[2]),parseInt(validfromDateTime.split("/")[0])-1,parseInt(validfromDateTime.split("/")[1]));
            validfromDateTime = formatTo2Digits(localDateTime.getUTCMonth()+1)+"/"+formatTo2Digits(localDateTime.getUTCDate())+"/"+localDateTime.getUTCFullYear();

            if(claimTime && claimTime.length>0){//convert to UTC
              localDateTime.setHours(parseInt(claimTime.split(":")[0].trim()));
              localDateTime.setMinutes(parseInt(claimTime.split(":")[1].trim()));
              validfromDateTime = validfromDateTime+" "+formatTo2Digits(localDateTime.getUTCHours())+":"+formatTo2Digits(localDateTime.getUTCMinutes());
            }
            else
              validfromDateTime = validfromDateTime+(defaultTime && defaultTime.trim().length>0?" "+defaultTime:"");  

            return validfromDateTime;
        }
    }

	export {
    	isValidString,
        copyFromObject,
        formatTo2Digits,
        textToClaimObject,
        createClaimDateTime
	}