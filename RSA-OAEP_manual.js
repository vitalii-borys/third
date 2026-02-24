let start = performance.now();

function isPrime(num) {
    var sqrtnum=BigInt(Math.floor(Math.sqrt(Number(num))));
    var prime = num != 1n;
    for(var i=2n; i<sqrtnum+1n; i++) {
        if(num % i == 0n) {
            prime = false;
            break;
        }
    }
    return prime;
}
//decomposes n-1 into 2^s × d
function findSD(num){
    let s = 0n; let d = 1n; let n = num - 1n;
    while (n % 2n === 0n) {
        n = n / 2n;
        s = s + 1n;
    }
    d = n;
    return {s,d};
}
const whitneses = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
// single witness check
function millerRabinTest(num, a) {
    const myP = findSD(num);
    let d = myP.d;
    let x = powMod(a,d,num); 
    if (x === 1n) {
        return true;
    } else {
        for (let r = 0n; r < myP.s; r++) {
            if (x === num - 1n) {
                return true;
            } else {
                x = (x * x) % num;
            }
        }
        return false;
    }
}
// fast modular exponentiation
function powMod(base, exp, mod) {
    let res = 1n;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            res = (res * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return res;
}
// runs multiple witnesses for reliability
function millerRabin(num) {
    for (let i = 0; i < whitneses.length; i++) {
        if (millerRabinTest(num, whitneses[i]) === false) {
            return false;
        }
    }
    return true;
}

/* const semiPrimeNumber  = 63773387n;
const semiPrimeNumber  = 313591n;
console.log("Our modulus N is:", typeof(semiPrimeNumber), semiPrimeNumber);
const primeArray = [];
for (let i = 3n; i < semiPrimeNumber / 2n; i++) {
    if (isPrime(i)) {
        primeArray.push(i);
    }
}
console.log(primeArray); */
// find prime numbers which are multipliers to get our big semi prime number
/* const multipiers = [];
for (let a = 0; a < primeArray.length; a++) {
    for (let b = 0; b < primeArray.length; b++) {
        if (primeArray[a] * primeArray[b] === semiPrimeNumber) {
            if (!multipiers.includes(primeArray[a] || !multipiers.includes(primeArray[a]))) {
                multipiers.push(primeArray[a]);
                multipiers.push(primeArray[b]);
            }
        }
    }
}
console.log("prime multipliers for totient phi:", multipiers[0], " * ", multipiers[1], " = ", multipiers[0] * multipiers[1]);
const q = multipiers[0]; const p = multipiers[1]; */

function getRandomArbitrary(min, max) {
    const r = BigInt(Math.floor(Math.random() * (max - min) + min));
    if (!millerRabin(r)) {
        return getRandomArbitrary(min, max);
    } else {
        return r;
    }
}
const arbitraryExponent = 29; const minimumNumber = Math.pow(2, arbitraryExponent);
let q = getRandomArbitrary(minimumNumber, minimumNumber * 2); let p = getRandomArbitrary(minimumNumber * 2, minimumNumber * 4);
const semiPrimeNumber = p * q;
console.log("p = (", p, " * (", q, ") =", semiPrimeNumber, toString(semiPrimeNumber).length);
const phi = (q - 1n) * (p - 1n);
console.log("phi = (", q, " - 1) * (", p, " - 1) =", phi, toString(phi).length); // 312472
// find first half of all prime numbers from 3 to phi
/* let eArray = [];
for (let i = 3n; i < BigInt(Math.floor(Number(phi) / 2)); i++) {
    if (isPrime(i)) {
        eArray.push(i);
    }
} */
// check if it contains arbitrary prime number 65537
//console.log("array for e with length", eArray.length, "contains 65537", eArray.includes(65537n), " at index ", eArray.indexOf(65537n));
// Chose Public key e which has to be: 1) a prime number 2) less then a totient phi 3) must not be a factor of the totient phi - phi/d != 0;
//const e = eArray[Math.floor(eArray.length / 2.1975233144779085766702339091882)];

//Brute force approach to get e and phi from 313591n take 1.5 sec so we just accept
//const phi = 312472n;
const e = 65537n;
//const e = 13752073n;
//console.log(e, " is chosen e");
// find greatest common divider for phi and e
function gcd(a, b, quotients = []) {
    if (a == 0 && b == 0) {
        console.log("Can't divide by zero!");
        return;
    } else if (a === 0n) {
        return b;
    } else if (b === 0n) {
        return { gcd: a, "quotients": quotients };
    }
    //console.log("a % b: ", a, " % ", b, " = ", a % b, " and quotient is: ", Math.floor(Number(a) / Number(b)));
    if (b !== 0n) {
        const quotient = Math.floor(Number(a) / Number(b));
        quotients.push(quotient);
        const remainder = a % b;
        a = b;
        b = remainder;
        return gcd(a, b, quotients);
    }
}
/* const gcdObject = gcd(e, phi);
console.log("Greatest common divider of e", e, "and phi", phi, "=", gcdObject.gcd, "so we chose phi and e correctly", gcdObject.gcd === 1n); */

// Find private key which has to be (d*e)%phi=1 takes 0.2 ms
function getKey(a, b, storedPhi, tOld = 0n, tNew = 1n) {
    let e = a; let phi = b; const phiStored = BigInt(storedPhi);
    if (e === 0n) {
        if (BigInt(tOld) < 0n) {
            console.log("tOld =", Number(tOld) + " + phi", phiStored, " = ", phiStored + tOld);
            tOld = phiStored + tOld;
        }
        return { tOld, tNew };
    }
    //console.log("phi % e: ", phi, " % ", e, " = ", phi % e, " and quotient is: ", Math.floor(Number(phi) / Number(e)));
    if (phi !== 0n) {
        const quotient = Math.floor(Number(phi) / Number(e));
        const remainder = phi % e;
        //console.log("tNew = tOld", Number(tOld), " - (quotient ", quotient, " * tNew", tNew, ")", " = ", Number(tOld) - (Number(quotient) * Number(tNew)));
        let tCurrent = BigInt(tOld) - (BigInt(quotient) * BigInt(tNew));
        tOld = tNew;
        tNew = tCurrent;
        phi = e;
        e = remainder;
        return getKey(e, phi, storedPhi, tOld, tNew);
    }
}
const keyObject = getKey(e, phi, phi);
console.log("Private key:", keyObject.tOld, toString(keyObject.tOld).length, "Verified:", e * keyObject.tOld % phi === 1n);
privateKey = keyObject.tOld;
//const privateKey = 194553n;

// brute forcing time to find private key grows substantially for bigger numbers compared to Euler's approach
// from 0.4ms to 8ms for modulus N 63773387
function bruteForcePrivateKey(e, phi) {
    console.log("Brute forcing...",e, phi);
    for (let key = 0n; key <= phi; key++) {
        if ((key*e)%phi === 1n) {
            return key;
        }
    }
}
/* const bruteForcedPrivateKey = bruteForcePrivateKey(e, phi);
console.log("Brute forced key private key", bruteForcedPrivateKey, "verified:", (e * bruteForcedPrivateKey) % phi === 1n); */

function modulo (n, d) {
    return ((n % d) + d) % d;
}

function nToBinary(number){
        let resultArray = [];
        while (number > 0n) {
            let b = number % 2n;
            if (b === 1) {
                number = (number - 1n) / 2n;
            } else {
                number = number / 2n;
            }
            resultArray.push(b);
        }
        return resultArray;
}

function modularExponentiation (n, exp, mod) {
    let i = 1n; let res = n; let expAr = []; let modAr = [];
    while (i < exp) {
        if (i % 2n == 1n) {
            res = (n ** i) % mod;
        } else {
            res = (res * res) % mod
        }
        expAr.push(i);
        modAr.push(res);
        i = i * 2n;
    }
    //console.log("squares till exponent", exp, expAr);
    //console.log("modular results for these squares", modAr);
    const binaryN = nToBinary(exp);
    //console.log("binary representation of exponent", binaryN);
    let multiplicationArray = [];
    for (let i = 0; i < expAr.length; i++) {
        if (binaryN[i] === 1n) {
            multiplicationArray.push(modAr[i]);
        }
    }
    let multiplicationResult = multiplicationArray[0];
    for (let i = 1; i < multiplicationArray.length; i++) {
        multiplicationResult = multiplicationResult * multiplicationArray[i];
    }
    console.log("multiply these values", multiplicationArray, "%", mod, "=", multiplicationResult % mod);
    multiplicationResult = multiplicationResult % mod;
    return multiplicationResult;
}

function stringToBigInt(text) {
    let res = 0n; let sq = BigInt(text.length) - 1n;
    for (let i = 0n; i < (BigInt(text.length)); i++) {
        res = BigInt(res + BigInt(text.charCodeAt(Number(i))) * (65536n ** sq));
        sq--;
    }
    return res;
}

function bigIntToString(bigIntValue) {
    let s = [];
    while (bigIntValue > 0n) {
        s = String.fromCharCode(Number(bigIntValue % 65536n)) + s;
        bigIntValue = bigIntValue / 65536n;
    }
    return s;
}

// the biggest number-message we can encode is semiprimenumber - 1
// Ciphertext = (Message ^ e) mod n
// Original Message = (Ciphertext ^ d) mod n

const message = "Прив";
// Naive approach takes 30 ms
/* const calculationResultEn = BigInt((message ** e) % semiPrimeNumber);
const calculationResultDe = BigInt((calculationResultEn ** privateKey) % semiPrimeNumber);
console.log("Calculating (", message, "^", e, ") % ", semiPrimeNumber, "should be equal to", calculationResultEn);
console.log("Calculating (", calculationResultEn, "^", privateKey, ") % ", semiPrimeNumber, "should be equal to", calculationResultDe); */

// Verbose approach takes 0.5ms
const numberedText = stringToBigInt(message);
console.log("encoded text", numberedText);
const myEncryptedMessage = modularExponentiation(numberedText, e, semiPrimeNumber);
console.log("myEncryptedMessage", myEncryptedMessage);
const myDecryptedMessage = modularExponentiation(myEncryptedMessage, privateKey, semiPrimeNumber);
console.log("myDecryptedMessage", myDecryptedMessage);
let messagedNumber = bigIntToString(myDecryptedMessage);
console.log(messagedNumber);

// Internet approach takes 0.2 ms
/* function powMod(base, exp, mod) {
    let res = 1n;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            res = (res * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2n;
    }
    return res;
} */
/* const enc = powMod(message, e, semiPrimeNumber);
console.log(enc);
const dec = powMod(enc, privateKey, semiPrimeNumber);
console.log(dec); */

let end = performance.now();
console.log(end - start, "ms");