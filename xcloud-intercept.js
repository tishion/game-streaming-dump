 /**
 *
 * The script to intercept the xCloud game streaming application.
 * 
 * Sheen Tian @ 2019-11-21-13:24:12
 */

/**
 * The pointer of the fuction to get the queue buffer
 */
var AMediaCodec_getInputBuffer = null;

/**
 * The module list
 */
var MODULES = [
    {
        name: 'libmediandk.so',
        skip: false,
        exports: [
            {
                symbol: 'AMediaCodec_queueInputBuffer',
                name: 'AMediaCodec_queueInputBuffer',
                skip: false,
                onEnter: function (args) {
                    var codec_ctx = args[0];
                    var idx = args[1];
                    var offset = args[2];
                    var size = args[3];
                    var ts = args[4];
                    // console.log('AMediaCodec_queueInputBuffer('
                    // + codec_ctx + ', '
                    // + idx + ', '
                    // + offset + ', '
                    // + size + ', '
                    // + ts + ')');

                    // Get the buffer data
                    var size_ptr = Memory.alloc(4);
                    var buf_ptr = AMediaCodec_getInputBuffer(args[0], args[1].toInt32(), size_ptr);
                    // console.log("======= buffer: " + buf_ptr + ", size: " + size);

                    send('es', buf_ptr.readByteArray(size.toInt32()));
                },
                onLeave: function (ret) { }
            },
            {
                symbol: 'AMediaFormat_setInt32',
                name: 'AMediaFormat_setInt32',
                skip: false,
                onEnter: function (args) {
                    var key_name_ptr = args[1];
                    console.log('AMediaFormat_setInt32('
                        + args[0] + ', '
                        + '"' + key_name_ptr.readCString() + '", '
                        + args[2] +
                        ')');
                },
                onLeave: function (ret) { }
            },
            {
                symbol: 'AMediaFormat_setString',
                name: 'AMediaFormat_setString',
                skip: false,
                onEnter: function (args) {
                    var key_name_ptr = args[1];
                    var val_ptr = args[2];
                    console.log('AMediaFormat_setString('
                        + args[0] + ', '
                        + '"' + key_name_ptr.readCString() + '", '
                        + '"' + val_ptr.readCString() + '", ' +
                        ')');
                },
                onLeave: function (ret) { }
            },
            {
                symbol: 'AMediaFormat_setBuffer',
                name: 'AMediaFormat_setBuffer',
                skip: false,
                onEnter: function (args) {
                    var key_name_ptr = args[1];
                    var buf_ptr = args[2];
                    var buf_len = args[3].toInt32();
                    var buf = buf_ptr.readByteArray(buf_len)

                    send(key_name_ptr.readCString(), buf);

                    var buf_str = Array.prototype.map.call(
                        new Uint8Array(buf),
                        function (x) {
                            return ('00' + x.toString(16)).slice(-2);
                        }).join(' ');

                    console.log('AMediaFormat_setBuffer('
                        + args[0] + ', '
                        + '"' + key_name_ptr.readCString() + '", '
                        + buf_str +
                        ')');
                },
                onLeave: function (ret) { }
            },
        ]
    },
    {
        name: 'libgamestreaming_native.so',
        skip: true,
        exports: [
            {
                symbol: '_ZN9Microsoft9Streaming15OpenGLVideoSink13onDataDecodedENSt6__ndk110shared_ptrINS_4Nano9Streaming11IDataHandleEEE',
                name: 'Microsoft::Streaming::OpenGLVideoSink::onDataDecoded',
                onEnter: function (args) {
                    console.log('===== on data decoded....');
                },
                onLeave: function (ret) { }
            }
        ]
    }
];

/**
 * Intercepts the function at the given address
 * @param {The address to be intercept} address 
 * @param {The export information} e 
 */
function intercept(address, e) {
    try {
        Interceptor.attach(address, e);
    } catch (exp) {
        console.error('Failed to intercept the export: ' + e.name + ', error: ' + exp);
    }
}

/**
 * Processes the exprot
 * @param {The module information} m 
 * @param {The export information} e 
 */
function process_export(m, e) {
    if (e.skip) {
        console.log('     !!!! Export skipped: ' + e.name);
        return;
    }
    try {
        var address = Module.findExportByName(m.name, e.symbol);
        if (address != null) {
            intercept(address, e);
            console.log('     **** Hook ' + e.name + ' @ ' + address);
        } else {
            console.error('     !!!! Export not found: ' + e.name);
        }
    } catch (exp) {
        console.error('     !!!! Failed to find the export: ' + e.name + ', error: ' + exp);
    }
}

/**
 * Processes the module
 * @param {The module list} modules 
 */
function do_hook(modules) {
    modules.forEach(function (m) {
        if (m.skip) {
            console.log('==== Module skipped: ' + m.name);
            return;
        }
        console.log('++++ Module ' + m.name);
        m.exports.forEach(function (e) {
            process_export(m, e);
        });
        console.log('---- Module ' + m.name);
    });
}

function do_init() {
    AMediaCodec_getInputBuffer = new NativeFunction(
        Module.findExportByName('libmediandk.so', 'AMediaCodec_getInputBuffer'),
        'pointer',
        ['pointer', 'int32', 'pointer']);
}

Java.perform(function () {
    do_init();
    do_hook(MODULES);
});