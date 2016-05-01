#ifndef __SCM_H__
#define __SCM_H__

//Snipped from scm.h

#define SCM_SVC_ES (0x10)
#define SCM_IS_ACTIVATED_ID (0x2)
#define SCM_SVC_UTIL (0x3)
#define TZ_UTIL_SEC_ALLOWS_MEMDUMP (0xB)
#define SCM_SVC_INFO (0x6)
#define TZ_INFO_GET_FEATURE_VERSION_ID (0x3)
#define TZ_INFO_GET_DIAG (0x2)
#define SCM_SVC_MP (0xC)
#define SCM_SVC_PIL (0x2)
#define PAS_SHUTDOWN_CMD (6)

//Undocumented

#define SCM_SVC_PRNG (0xA)
#define SCM_PRNG_GETDATA (1)
#define SCM_INIT_IMAGE (0x1)
#define XPU_ERR_FATAL (0xE)

#endif
