var SPHINX_debug = true;

/**
 * Sends data to the console if we're in debug mode
 * @param msg The string containing the message to display
 */
function SPHINX_dump(label, msg) {
    if (SPHINX_debug)
        console.log("|||||||||| SPHINX debug: " + label + ": " + msg + "\n");
}

function SPHINX_Tools(passwd, domain) {
    this.passwd = passwd;
    this.domain = domain;
    this.rho = null;
    this.alpha = null;
}

SPHINX_Tools.prototype = {

    ONE: new sjcl.bn('1'),
    // get prime p from https://safecurves.cr.yp.to/field.html
    bnp: new bnjs('115792089210356248762697446949407573530086143415290314195533631308867097853951', 10),

    r: sjcl.ecc.curves.c256.r,

    sjclbn2bnjs: function(sjclbn) {
        var str = sjcl.codec.hex.fromBits(sjclbn.toBits());
        // console.log("sjclstr:"+str);
        return new bnjs(str, 16);
    },

    bnjs2sjclbn: function(bnjsbn) {
        var str = bnjsbn.toString(16);
        return new sjcl.bn(str);
    },

    hash: function(passwd_str) {
        var hashbits = sjcl.hash.sha256.hash(passwd_str);
        return sjcl.codec.hex.fromBits(hashbits);
    },

    hashIntoEC: function(passwd) {
        passwd_hex = hash(passwd);
        var curve = sjcl.ecc.curves.c256;

        // get y^2 = x^3+a*x+b params
        var a = new sjcl.bn(curve.a.toString());
        var bna = sjclbn2bnjs(a);
        var b = new sjcl.bn(curve.b.toString());
        var bnb = sjclbn2bnjs(b);

        // init
        var x = new sjcl.bn(passwd_hex);
        var redp = bnjs.red(bnp);
        var P;
        var found = false;
    
        while (!found) {
            // calculate b + (x*(a+(x^2))) => b+ax+x^3
            var s = b.add(x.mul(a.add(x.mul(x).normalize())).normalize());
            var bns = sjclbn2bnjs(s);
            var reds = bns.toRed(redp);
            try {
                // try to calculate modular square root
                y = bnjs2sjclbn(reds.redSqrt());
                
                P = new sjcl.ecc.point(
                    sjcl.ecc.curves.c256,
                    new sjcl.bn.prime.p256(x.toString()),
                    new sjcl.bn.prime.p256(y.toString())
                );
                if (P.isValid()) found = true;
            } catch {
            } finally {
                x = x.add(ONE);
            }
        }
        return P;
    },

    Fk: function(x, k) {
        hash_point = hashIntoEC(x);
        test = hash_point.mult(k);
        hpxk = hash_point.mult(k).toBits();
        hpxk_str = sjcl.codec.hex.fromBits(hpxk);
        str = x+hpxk_str;
        return hash(str);
    },

    getRho: function() {
        var numWords = 8;
        var rand;
        if (sjcl.random.isReady() > 0) {
            SPHINX_dump("sjcl random ready?", sjcl.random.isReady());
            rand_bits = sjcl.random.randomWords(numWords);
            rand_str = sjcl.codec.hex.fromBits(rand_bits);
            rand = new sjcl.bn(rand_str);
            // make sure rho belong to Zq
            rand = rand.mod(r);
    
            return rand;
        } else {
            console.log("sjcl random not ready!");
        }
    },

    getAlpha: function(str, rho) {
        var EC_hash_result = hashIntoEC(str);
        var alpha = EC_hash_result.mult(rho);
        return alpha;
    },

    reconstructRWD(passwd, domain, beta, rho) {
        // Question: what's the difference between r and p? why use p in calculating point, while use r in calculating inverse?
        var rho_inverse = rho.inverseMod(r);
        beta_power_rho_inverse_str = sjcl.codec.hex.fromBits(beta.mult(rho_inverse).toBits());
        // console.log("second:"+passwd + domain + beta_power_rho_inverse_str);
        var rwd = hash(passwd + domain + beta_power_rho_inverse_str);
        // console.log("reconstruct rwd:"+rwd);
        return rwd;
    }
}