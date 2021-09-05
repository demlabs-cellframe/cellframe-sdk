#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFArray.h>
#include <CoreFoundation/CFString.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "dap_network_monitor.h"
#include "dap_common.h"
#include "pthread_barrier.h"


#define LOG_TAG "dap_network_monitor"

static SCDynamicStoreRef s_store = NULL;
static CFRunLoopSourceRef s_rls;
#define __bridge

static void* network_monitor_worker(void *arg);

static struct {
    CFRunLoopRef rlref;
    pthread_t thread;
    dap_network_monitor_notification_callback_t callback;
} _net_notification;


void watch_for_network_changes()
{
    SCDynamicStoreContext context = { 0, (void *)s_store, NULL, NULL, NULL };

    s_store = SCDynamicStoreCreate(NULL, CFSTR("watch_for_network_changes"), _net_notification.callback, &context);
    if (!s_store) {
        log_it(L_ERROR, "Could not open session with config.error = %s\n", SCErrorString(SCError()));
        return;
    }

/*
* establish and register dynamic store keys to watch
* - global IPv4 configuration changes (e.g. new default route)
* - per-service IPv4 state changes (IP service added/removed/...)
*/
    CFStringRef           key1 =    SCDynamicStoreKeyCreateNetworkGlobalEntity      (NULL, kSCDynamicStoreDomainState, kSCEntNetIPv4);
    CFStringRef           key2 =    SCDynamicStoreKeyCreateNetworkInterfaceEntity   (NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
    CFStringRef           key3 =    SCDynamicStoreKeyCreateNetworkServiceEntity     (NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
    CFStringRef           pattern1  = SCDynamicStoreKeyCreateNetworkInterfaceEntity (NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
    CFStringRef           pattern2  = SCDynamicStoreKeyCreateNetworkInterfaceEntity (NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetInterface);
    CFStringRef           pattern3  = SCDynamicStoreKeyCreateNetworkGlobalEntity    (NULL, kSCDynamicStoreDomainState, kSCEntNetIPv4);
    CFStringRef           pattern4  = SCDynamicStoreKeyCreateNetworkGlobalEntity    (NULL, kSCDynamicStoreDomainState, kSCEntNetInterface);
    CFStringRef           pattern5  = SCDynamicStoreKeyCreateNetworkServiceEntity   (NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
    CFStringRef           pattern6  = SCDynamicStoreKeyCreateNetworkServiceEntity   (NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetInterface);
    CFMutableArrayRef     keys = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    CFMutableArrayRef     patterns = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

    if (!key1 || !key2 || !key3 || !keys || !pattern1 || !pattern2 || !pattern3 || !pattern4 || !pattern5 || !pattern6 || !patterns) goto error;

    CFArrayAppendValue(keys, key1);
    CFArrayAppendValue(keys, key2);
    CFArrayAppendValue(keys, key3);
    CFArrayAppendValue(patterns, pattern1);
    CFArrayAppendValue(patterns, pattern2);
    CFArrayAppendValue(patterns, pattern3);
    CFArrayAppendValue(patterns, pattern4);
    CFArrayAppendValue(patterns, pattern5);
    CFArrayAppendValue(patterns, pattern6);

    if (SCDynamicStoreSetNotificationKeys(s_store, keys, patterns)){
        s_rls = SCDynamicStoreCreateRunLoopSource(NULL, s_store, 0);
        if (s_rls) {
            CFRunLoopAddSource(CFRunLoopGetCurrent(), s_rls, kCFRunLoopDefaultMode);
        }else{
            log_it(L_ERROR, "SCDynamicStoreCreateRunLoopSource failed: %s\n", SCErrorString(SCError()));
            CFRelease(s_store);
        }
    }else {
        log_it(L_ERROR, "SCDynamicStoreSetNotificationKeys failed: %s\n", SCErrorString(SCError()));
        CFRelease(s_store);
    }
    goto exit;

    error:
    if (s_store)    CFRelease(s_store);

    exit:
    if (key1) CFRelease(key1);
    if (key2) CFRelease(key2);
    if (key3) CFRelease(key3);
    if (pattern1) CFRelease(pattern1);
    if (pattern2) CFRelease(pattern2);
    if (pattern3) CFRelease(pattern3);
    if (pattern4) CFRelease(pattern4);
    if (pattern5) CFRelease(pattern5);
    if (pattern6) CFRelease(pattern6);
    if (keys) CFRelease(keys);
    if (patterns) CFRelease(patterns);
    return;
}


/**
 * @brief dap_network_monitor_init
 * @param callback
 * @details starts network monitorting
 * @return 0 if successful
 */
int dap_network_monitor_init(dap_network_monitor_notification_callback_t cbMonitorNatification)
{
    memset((void*)&_net_notification, 0, sizeof(_net_notification));
    _net_notification.callback = cbMonitorNatification;

    pthread_barrier_t barrier;

    pthread_barrier_init(&barrier, NULL, 2);
    if(pthread_create(&_net_notification.thread, NULL, network_monitor_worker, &barrier) != 0) {
        log_it(L_ERROR, "Error create notification thread");
        return -3;
    }

    pthread_barrier_wait(&barrier);

    pthread_barrier_destroy(&barrier);

    log_it(L_INFO, "dap_network_monitor was initialized");
    return 0;
}

/**
 * @brief dap_network_monitor_deinit
 */
void dap_network_monitor_deinit(void)
{
    CFRunLoopStop(_net_notification.rlref);
    //log_it(L_INFO, "After stopping run loop cycle");
    pthread_cancel(_net_notification.thread);
    //log_it(L_INFO, "After cancelation monitor thread!");
    pthread_join(_net_notification.thread, NULL);
    //log_it(L_INFO, "After deinit that wonderfull monitor!");
}



static void* network_monitor_worker(void *arg)
{
    pthread_barrier_t *barrier = (pthread_barrier_t *)arg;
    watch_for_network_changes();
    pthread_barrier_wait(barrier);
    _net_notification.rlref = CFRunLoopGetCurrent();
    CFRunLoopRun();
    log_it(L_WARNING, "We are in the loop activity and won't have to see this message!");
    return NULL;
}





////////////////////////////////////////////////////////////////
// Usefull functions for future processing changes to interfaces

static OSStatus MoreSCErrorBoolean(Boolean success)
{
    OSStatus err;
    int scErr;

    err = noErr;
    if ( ! success ) {
        scErr = SCError();
        if (scErr == kSCStatusOK) {
            scErr = kSCStatusFailed;
        }
        // Return an SCF error directly as an OSStatus.
        // That's a little cheesy.  In a real program
        // you might want to do some mapping from SCF
        // errors to a range within the OSStatus range.
        err = scErr;
    }
    return err;
}

static OSStatus MoreSCError(const void *value)
{
    return MoreSCErrorBoolean(value != NULL);
}

static OSStatus CFQError(CFTypeRef cf)
    // Maps Core Foundation error indications (such as they
    // are) to the OSStatus domain.
{
    OSStatus err;

    err = noErr;
    if (cf == NULL) {
        err = -4960;
    }
    return err;
}

static void CFQRelease(CFTypeRef cf)
    // A version of CFRelease that's tolerant of NULL.
{
    if (cf != NULL) {
        CFRelease(cf);
    }
}


static void GetIPAddressListFromValue(const void *key,
                                      const void *value,
                                      void *context)
    // This function is a callback CopyIPAddressListSCF when
    // it calls CFDictionaryApplyFunction.  It extracts the
    // IPv4 address list from the network service dictionary
    // and appends it to the result dictionary (which is passed
    // in via the context pointers).
{
    CFArrayRef intfAddrList;

    assert( key != NULL );
    assert( CFGetTypeID(key) == CFStringGetTypeID() );
    assert( value != NULL );
    assert( CFGetTypeID(value) == CFDictionaryGetTypeID() );
    assert( context != NULL );
    assert( CFGetTypeID(context) == CFArrayGetTypeID() );

    //CFDictionaryRef _value = (CFDictionaryRef) value;
    struct __CFDictionary * _value = (__bridge struct __CFDictionary *) value;
    intfAddrList = (__bridge struct __CFArray *) CFDictionaryGetValue(_value,
                            kSCPropNetIPv4Addresses);
    if (intfAddrList != NULL) {
        assert( CFGetTypeID(intfAddrList)
                == CFArrayGetTypeID() );
        struct __CFArray * _context = (__bridge struct __CFArray *) context;
        CFArrayAppendArray(_context,
                            intfAddrList,
                            CFRangeMake(0, CFArrayGetCount(intfAddrList))
                            );
    }

}

static OSStatus CopyIPAddressListSCF(CFArrayRef *addrList)
    // Returns a CFArray that contains every IPv4
    // address on the system (as CFStrings) in no
    // particular order.
{
    OSStatus            err;
    SCDynamicStoreRef   ref;
    CFStringRef         pattern;
    CFArrayRef          patternList;
    CFDictionaryRef     valueDict;
    CFMutableArrayRef   result;

    assert( addrList != NULL);
    assert(*addrList == NULL);

    ref         = NULL;
    pattern     = NULL;
    patternList = NULL;
    valueDict   = NULL;
    result      = NULL;

    // Create a connection to the dynamic store, then create
    // a search pattern that finds all IPv4 entities.
    // The pattern is "State:/Network/Service/[^/]+/IPv4".
    ref = SCDynamicStoreCreate( NULL,
                                CFSTR("CopyIPAddressListSCF"),
                                NULL,
                                NULL);
    err = MoreSCError(ref);
    if (err == noErr) {
        pattern = SCDynamicStoreKeyCreateNetworkInterfaceEntity(
                                NULL,
                                kSCDynamicStoreDomainState,
                                kSCCompAnyRegex,
                                kSCEntNetIPv4);
        err = MoreSCError(pattern);
    }

    // Now make a pattern list out of the pattern and then
    // call SCDynamicStoreCopyMultiple.  We use that call,
    // rather than repeated calls to SCDynamicStoreCopyValue,
    // because it gives us a snapshot of the state.
    if (err == noErr) {
        patternList = CFArrayCreate(NULL,
                                    (const void **) &pattern,
                                    1,
                                    &kCFTypeArrayCallBacks);
        err = CFQError(patternList);
    }
    if (err == noErr) {
        valueDict = SCDynamicStoreCopyMultiple(ref,
                                               NULL,
                                               patternList);
        err = MoreSCError(valueDict);
    }

    // For each IPv4 entity that we found, extract the list
    // of IP addresses and append it to our results array.
    if (err == noErr) {
        result = CFArrayCreateMutable(NULL, 0,
                                      &kCFTypeArrayCallBacks);
        err = CFQError(result);
    }

    // Iterate over the values, extracting the IP address
    // arrays and appending them to the result.
    if (err == noErr) {
        CFDictionaryApplyFunction(valueDict,
                                  GetIPAddressListFromValue,
                                  result);
    }
    // Clean up.

    if(valueDict)
        CFQRelease(valueDict);
    if(ref)
        CFQRelease(ref);
    if(pattern)
        CFQRelease(pattern);
    if(patternList)
        CFQRelease(patternList);

    if (err != noErr && result != NULL) {
        CFQRelease(result);
        result = NULL;
        printf("10\n");
    }
    *addrList = result;

    assert( (err == noErr) == (*addrList != NULL) );

    return err;
}
