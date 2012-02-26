/*
 * base64_decode.js
 * code by Nicholas C. Zakas
 * posted at http://www.nczonline.net/blog/2009/12/08/computer-science-in-javascript-base64-encoding/
 *
 */

function base64Decode(text){

    text = text.replace(/\s/g,"");

    if(!(/^[a-z0-9\+\/\s]+\={0,2}$/i.test(text)) || text.length % 4 > 0){
        throw new Error("Not a base64-encoded string.");
    }   

    //local variables
    var digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        cur, prev, digitNum,
        i=0,
        result = [];

    text = text.replace(/=/g, "");

    while(i < text.length){

        cur = digits.indexOf(text.charAt(i));
        digitNum = i % 4;

        switch(digitNum){

            //case 0: first digit - do nothing, not enough info to work with

            case 1: //second digit
                result.push(String.fromCharCode(prev << 2 | cur >> 4));
                break;

            case 2: //third digit
                result.push(String.fromCharCode((prev & 0x0f) << 4 | cur >> 2));
                break;

            case 3: //fourth digit
                result.push(String.fromCharCode((prev & 3) << 6 | cur));
                break;
        }

        prev = cur;
        i++;
    }

    return result.join("");
}
