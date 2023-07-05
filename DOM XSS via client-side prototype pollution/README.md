<!-- https://0a090099032aa09f8356aa91009900c0.web-security-academy.net/?__proto__[value]=data:,alert(%27poluted%27) -->
## DOM XSS via client-side prototype pollution

In this challenge, we need to perform a client-side prototype polution that will causing a DOM xss. We were given a website that able to do search, feedback, login, etc.

![image](https://github.com/DJumanto/TryHackMe/assets/100863813/d0d02201-958e-4282-bcb8-4b1e082b5b59)

Let's focus on the source code first.

**deparam.js**
```js
var deparam = function( params, coerce ) {
    var obj = {},
        coerce_types = { 'true': !0, 'false': !1, 'null': null };

    if (!params) {
        return obj;
    }

    params.replace(/\+/g, ' ').split('&').forEach(function(v){
        var param = v.split( '=' ),
            key = decodeURIComponent( param[0] ),
            val,
            cur = obj,
            i = 0,

            keys = key.split( '][' ),
            keys_last = keys.length - 1;

        if ( /\[/.test( keys[0] ) && /\]$/.test( keys[ keys_last ] ) ) {
            keys[ keys_last ] = keys[ keys_last ].replace( /\]$/, '' );
            keys = keys.shift().split('[').concat( keys );
            keys_last = keys.length - 1;
        } else {
            keys_last = 0;
        }

        if ( param.length === 2 ) {
            val = decodeURIComponent( param[1] );

            if ( coerce ) {
                val = val && !isNaN(val) && ((+val + '') === val) ? +val        // number
                    : val === 'undefined'                       ? undefined         // undefined
                        : coerce_types[val] !== undefined           ? coerce_types[val] // true, false, null
                            : val;                                                          // string
            }

            if ( keys_last ) {
                for ( ; i <= keys_last; i++ ) {
                    key = keys[i] === '' ? cur.length : keys[i];
                    cur = cur[key] = i < keys_last
                        ? cur[key] || ( keys[i+1] && isNaN( keys[i+1] ) ? {} : [] )
                        : val;
                }

            } else {
                if ( Object.prototype.toString.call( obj[key] ) === '[object Array]' ) {
                    obj[key].push( val );

                } else if ( {}.hasOwnProperty.call(obj, key) ) {
                    obj[key] = [ obj[key], val ];
                } else {
                    obj[key] = val;
                }
            }

        } else if ( key ) {
            obj[key] = coerce
                ? undefined
                : '';
        }
    });

    return obj;
};
```

**searchLogger.js**
```js
async function logQuery(url, params) {
    try {
        await fetch(url, {method: "post", keepalive: true, body: JSON.stringify(params)});
    } catch(e) {
        console.error("Failed storing query");
    }
}

async function searchLogger() {
    let config = {params: deparam(new URL(location).searchParams.toString())};

    if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }

    if(config.params && config.params.search) {
        await logQuery('/logger', config.params);
    }
}

window.addEventListener("load", searchLogger);
```

**deparam.js** is a function that will work on parsing the query parameter, and create a new object from it. if there is a square bracket `[]` in the params such as `foo[bar][lar]`, then it will iterate throughout the keys and it will check if the value of the key is existed. such as if the value of `foo[bar][lar]` is a array, then the `val` which was splited by the `=` symbol, will be appended to the array, if it was a single value, then it will convert the type of value to array then pushed both the first value and the new `val`. If it was a new key, then it will create a new key with new value, `val`.

**searchLogger.js** will assign `config` by the value of the parameters we inserted in the query. it will check if there is a `transport_url` key, and `search` key. if there's a `transport_url` key, then it will create a new script tag with the source coming from the `transport_url` value which is a type of sink. and if there's a `search` key, which is the search parameter in the query, it will pass the parameters to the function called `logQuery`, to find what user want to search.

The problem is, we able to polute the `Object.prototype` using the `transport_url`. we can do things like this

```txt
http://somewebsite/?__proto__[transport_url]=test123
```

based on this piece of code if there's a `transport_url` key in the config Object, it will create an new script with the source coming from it's value:

```js
if(config.transport_url) {
        let script = document.createElement('script');
        script.src = config.transport_url;
        document.body.appendChild(script);
    }
```

![image](https://github.com/DJumanto/TryHackMe/assets/100863813/22ccc1ec-afe9-49bc-94e7-35a29071c98d)

We can also see that the global object also has the `transport_url` key with `test 123` value.

![image](https://github.com/DJumanto/TryHackMe/assets/100863813/7d9ba5fc-72b8-4c50-ab8d-ec3958d290d5)

Now let's try to do a DOM based xss attack, here's how we gonna do it. we have access to insert the script tag source, it means, we can control where the source of the code is coming from. It can be our exploit server that has a javascript code that will take the credentials, session, cookies, etc. In this case, let's just execute javascript code that will trigger an alert. The final payload will be like this:

```txt
http://somewebsite/?__proto__[transport_url]=data:,alert('poluted!');
```

The result will be as below

![image](https://github.com/DJumanto/TryHackMe/assets/100863813/e39f0d64-b239-461a-bd47-d00d20593d00)


