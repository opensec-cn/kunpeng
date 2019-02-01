'use strict'

// npm install ffi
var ffi = require('ffi');

// mac下要把链接库后缀改为.dylib
var kunpeng = ffi.Library('./kunpeng_c', {
    'GetPlugins': ['string',[]],
    'Check': ['string',['string']],
    'SetConfig': ['int',['string']],
    'ShowLog':['int',[]]
});

kunpeng.ShowLog()
var plugins = kunpeng.GetPlugins();
console.log(plugins);
var task = {
    'type': 'web',
    'netloc': 'http://www.google.cn',
    'target': 'web'
}
var result = kunpeng.Check(JSON.stringify(task))
console.log(result);
