/******************************************************************************
* Copyright (c) 2010, 2014  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
*
* Contributors:
*   Timea Moder - initial implementation and initial documentation
*   Attila Balasko
*   Kulcsár Endre
******************************************************************************/
//
//  File:               RTSP_EncDec.cc
//  Description:        Encoding decoding functions for RTSP protocol modules
//  Rev:                R2B
//  Prodnr:             CNL 113 588

#include "RTSP_Types.hh"
#include <ctype.h>
#include "memory.h"

// Memory management functions from TITAN
extern "C" {

  // Same as the standard c malloc(), but it never returns NULL.
  // It increases a malloc counter. Exits if there is not enough memory.
  extern void *Malloc(size_t size);

  // Same as the standard c realloc(), but it never returns NULL if size is
  // positive. It updates the malloc or free counters if necessary.
  // Exits if there is not enough memory.
  extern void *Realloc(void *ptr, size_t size);

  // Same as the standard c free(). It increases the free counter.
  extern void Free(void *ptr);
};

#define BUFFER_FAIL 2
#define BUFFER_CRLF 3

static bool report_lf=true;

namespace RTSP__Types {

//=========================================================================
//====             Working Functions                                    ===
//=========================================================================
  
//from AbstractSocket
//=======================================
//  log_debug
//=======================================
void log_debug(const bool debugging, const char *fmt, ...)
{
  if (debugging) {
    TTCN_Logger::begin_event(TTCN_DEBUG);
    va_list args;
    va_start(args, fmt);
    TTCN_Logger::log_event_va_list(fmt, args);
    va_end(args);
    TTCN_Logger::end_event();
  }
}
//=======================================
//  log_warning
//=======================================
void log_warning(const char *fmt, ...)
{
  TTCN_Logger::begin_event(TTCN_WARNING);
  va_list args;
  va_start(args, fmt);
  TTCN_Logger::log_event_va_list(fmt, args);
  va_end(args);
  TTCN_Logger::end_event();
}

//==== Encode HeaderFields: ====
//=======================================
// encodeHeaderField()
//=======================================
void encodeHeaderField(
    const char* headerName, 
    const OPTIONAL<CHARSTRING>& headerValue, 
    TTCN_Buffer& buf) 
{
  log_debug(tsp__RTSP__debugging, "RTSP_encodeHeaderField started");
  buf.put_cs(headerName);
  buf.put_cs( ": ");
  buf.put_cs(headerValue);
  buf.put_cs("\r\n");
}

//==== Encode ContentLength HeaderField: ====
//=======================================
// encodeContentLength()
//=======================================
void encodeContentLength(
    const char* headerName, 
    const OPTIONAL<CHARSTRING>& headerValue, 
    const INTEGER lengthOfBody,
    TTCN_Buffer& buf,
    const BOOLEAN& automaticContentLengthCalc) 
{
  log_debug(tsp__RTSP__debugging, "RTSP_encodeHeaderField started");
  if (automaticContentLengthCalc == true)
  {
    if (lengthOfBody>0)
    {
      buf.put_cs(headerName);
      buf.put_cs( ": ");
      buf.put_cs(int2str(lengthOfBody));
      buf.put_cs("\r\n");
    }
  }
  else{
  buf.put_cs(headerName);
  buf.put_cs( ": ");
  buf.put_cs(headerValue);
  buf.put_cs("\r\n");
  }
}

//=======================================
// Function RTSP_encodeHeader()
//=======================================
void RTSP_encodeHeader(
    const HeaderStruct* headerStruct, 
    TTCN_Buffer& buf,
    const INTEGER lengthOfBody,
    const BOOLEAN& automaticContentLengthCalc)
{
  log_debug(tsp__RTSP__debugging, "RTSP_encodeHeader started");
  if(headerStruct->accept().ispresent()) { encodeHeaderField("Accept", headerStruct->accept(), buf);}  //1
  if(headerStruct->acceptEncoding().ispresent()) { encodeHeaderField("Accept-Encoding", headerStruct->acceptEncoding(), buf);}
  if(headerStruct->acceptLanguage().ispresent()) { encodeHeaderField("Accept-Language", headerStruct->acceptLanguage(), buf);}
  if(headerStruct->allow().ispresent()) { encodeHeaderField("Allow", headerStruct->allow(), buf);}
  if(headerStruct->authorization().ispresent()) { encodeHeaderField("Authorization", headerStruct->authorization(), buf);}
  if(headerStruct->bandwidth().ispresent()) { encodeHeaderField("Bandwidth", headerStruct->bandwidth(), buf);}
  if(headerStruct->blocksize().ispresent()) { encodeHeaderField("Blocksize", headerStruct->blocksize(), buf);}
  if(headerStruct->cacheControl().ispresent()) { encodeHeaderField("Cache-Control", headerStruct->cacheControl(), buf);}
  if(headerStruct->conference().ispresent()) { encodeHeaderField("Conference", headerStruct->conference(), buf);}
  if(headerStruct->connection().ispresent()) { encodeHeaderField("Connection", headerStruct->connection(), buf);} //10
  if(headerStruct->contentBase().ispresent()) { encodeHeaderField("Content-Base", headerStruct->contentBase(), buf);}
  if(headerStruct->contentEncoding().ispresent()) { encodeHeaderField("Content-Encoding", headerStruct->contentEncoding(), buf);}
  if(headerStruct->contentLanguage().ispresent()) { encodeHeaderField("Content-Language", headerStruct->contentLanguage(), buf);}
  if((headerStruct->contentLength().ispresent()) || (lengthOfBody>0)) { encodeContentLength("Content-Length", headerStruct->contentLength(), lengthOfBody, buf, automaticContentLengthCalc);}
  if(headerStruct->contentLocation().ispresent()) { encodeHeaderField("Content-Location", headerStruct->contentLocation(), buf);}
  if(headerStruct->contentType().ispresent()) { encodeHeaderField("Content-Type", headerStruct->contentType(), buf);}
  if(headerStruct->cSeq().ispresent()) { encodeHeaderField("CSeq", headerStruct->cSeq(), buf);}
  if(headerStruct->date().ispresent()) { encodeHeaderField("Date", headerStruct->date(), buf);}
  if(headerStruct->expires().ispresent()) { encodeHeaderField("Expires", headerStruct->expires(), buf);}
  if(headerStruct->fromField().ispresent()) { encodeHeaderField("From", headerStruct->fromField(), buf);} //20
  if(headerStruct->host().ispresent()) { encodeHeaderField("Host", headerStruct->host(), buf);}
  if(headerStruct->ifMatch().ispresent()) { encodeHeaderField("If-Match", headerStruct->ifMatch(), buf);}
  if(headerStruct->ifModifiedSince().ispresent()) { encodeHeaderField("If-Modified-Since", headerStruct->ifModifiedSince(), buf);}
  if(headerStruct->lastModified().ispresent()) { encodeHeaderField("Last-Modified", headerStruct->lastModified(), buf);}
  if(headerStruct->location().ispresent()) { encodeHeaderField("Location", headerStruct->location(), buf);}
  if(headerStruct->proxyAuth().ispresent()) { encodeHeaderField("Proxy-Authenticate", headerStruct->proxyAuth(), buf);}
  if(headerStruct->proxyRequire().ispresent()) { encodeHeaderField("Proxy-Require", headerStruct->proxyRequire(), buf);}
  if(headerStruct->publicField().ispresent()) { encodeHeaderField("Public", headerStruct->publicField(), buf);}
  if(headerStruct->range().ispresent()) { encodeHeaderField("Range", headerStruct->range(), buf);}
  if(headerStruct->rdtFeatureLevel().ispresent()) { encodeHeaderField("RdtFeatureLevel", headerStruct->rdtFeatureLevel(), buf);}
  if(headerStruct->realChallenge1().ispresent()) { encodeHeaderField("RealChallenge1", headerStruct->realChallenge1(), buf);}
  if(headerStruct->reconnect().ispresent()) { encodeHeaderField("Reconnect", headerStruct->reconnect(), buf);}
  if(headerStruct->referer().ispresent()) { encodeHeaderField("Referer", headerStruct->referer(), buf);} 
  if(headerStruct->retryAfter().ispresent()) { encodeHeaderField("Retry-After", headerStruct->retryAfter(), buf);}
  if(headerStruct->require().ispresent()) { encodeHeaderField("Require", headerStruct->require(), buf);}
  if(headerStruct->rtcpInterval().ispresent()) { encodeHeaderField("Rtcp-Interval", headerStruct->rtcpInterval(), buf);}
  if(headerStruct->rtpInfo().ispresent()) { encodeHeaderField("RTP-Info", headerStruct->rtpInfo(), buf);}
  if(headerStruct->scale().ispresent()) { encodeHeaderField("Scale", headerStruct->scale(), buf);}
  if(headerStruct->speed().ispresent()) { encodeHeaderField("Speed", headerStruct->speed(), buf);}
  if(headerStruct->server().ispresent()) { encodeHeaderField("Server", headerStruct->server(), buf);}
  if(headerStruct->session().ispresent()) { encodeHeaderField("Session", headerStruct->session(), buf);}
  if(headerStruct->statsMask().ispresent()) { encodeHeaderField("StatsMask", headerStruct->statsMask(), buf);}
  if(headerStruct->timeStamp().ispresent()) { encodeHeaderField("Timestamp", headerStruct->timeStamp(), buf);}
  if(headerStruct->transport().ispresent()) { encodeHeaderField("Transport", headerStruct->transport(), buf);}
  if(headerStruct->unsupported().ispresent()) { encodeHeaderField("Unsupported", headerStruct->unsupported(), buf);} //40
  if(headerStruct->userAgent().ispresent()) { encodeHeaderField("User-Agent", headerStruct->userAgent(), buf);}
  if(headerStruct->vary().ispresent()) { encodeHeaderField("Vary", headerStruct->vary(), buf);}
  if(headerStruct->via().ispresent()) { encodeHeaderField("Via", headerStruct->via(), buf);}
  if(headerStruct->vsrc().ispresent()) { encodeHeaderField("Vsrc", headerStruct->vsrc(), buf);}
  if(headerStruct->wwwAuth().ispresent()) { encodeHeaderField("WWW-Authenticate", headerStruct->wwwAuth(), buf);} //44
  if(headerStruct->xRealUsestrackid().ispresent()) { encodeHeaderField("X-Real-Usestrackid", headerStruct->xRealUsestrackid(), buf);}
  //extra fields, not specified in RFC 2326 (RTSP), just mentioned in C.1.3
  if(headerStruct->xVigBno().ispresent()) { encodeHeaderField("X-Vig-Bno", headerStruct->xVigBno(), buf);}
  if(headerStruct->xVigMsisdn().ispresent()) { encodeHeaderField("X-Vig-Msisdn", headerStruct->xVigMsisdn(), buf);}
  if(headerStruct->xRetransmit().ispresent()) { encodeHeaderField("x-retransmit", headerStruct->xRetransmit(), buf);}
  if(headerStruct->xDynamicRate().ispresent()) { encodeHeaderField("x-dynamic-rate", headerStruct->xDynamicRate(), buf);}
  if(headerStruct->xTransportOptions().ispresent()) { encodeHeaderField("x-transport-options", headerStruct->xTransportOptions(), buf);}
  if(headerStruct->xPrebuffer().ispresent()) { encodeHeaderField("x-prebuffer", headerStruct->xPrebuffer(), buf);}
  if(headerStruct->xAction().ispresent()) { encodeHeaderField("X-Action", headerStruct->xAction(), buf);} 
  if(headerStruct->xEncodingFiles().ispresent()) { encodeHeaderField("X-EncodingFiles", headerStruct->xEncodingFiles(), buf);}   
  if(headerStruct->xUdpPipe().ispresent()) { encodeHeaderField("X-UdpPipe", headerStruct->xUdpPipe(), buf);}    
  if(headerStruct->xMbmsSync().ispresent()) { encodeHeaderField("X-MbmsSync", headerStruct->xMbmsSync(), buf);}   
  if(headerStruct->xBandwidth().ispresent()) { encodeHeaderField("X-Bandwidth", headerStruct->xBandwidth(), buf);}   
  if(headerStruct->xContent().ispresent()) { encodeHeaderField("X-Content", headerStruct->xContent(), buf);}       
  if(headerStruct->xFec().ispresent()) { encodeHeaderField("X-Fec", headerStruct->xFec(), buf);}      
  if(headerStruct->xUserPlaneDest().ispresent()) { encodeHeaderField("X-UserPlaneDest", headerStruct->xUserPlaneDest(), buf);}      
  if(headerStruct->xFluteBitrate().ispresent()) { encodeHeaderField("X-FluteBitrate", headerStruct->xFluteBitrate(), buf);}      
  if(headerStruct->xTsi().ispresent()) { encodeHeaderField("X-Tsi", headerStruct->xTsi(), buf);}   
  if(headerStruct->xContentFdtSendInterval().ispresent()) { encodeHeaderField("X-ContentFdtSendInterval", headerStruct->xContentFdtSendInterval(), buf);}       
  if(headerStruct->xReporting().ispresent()) { encodeHeaderField("X-Reporting", headerStruct->xReporting(), buf);}   
          
  log_debug(tsp__RTSP__debugging, "RTSP_encodeHeader extensionHeaders follows");
  //extensionHeaders:  
  unsigned int i=0;
  if( headerStruct->extensionHeaders().ispresent()) {
    unsigned int size = headerStruct->extensionHeaders()().size_of();
    for(;i<size; i++)
    {
      encodeHeaderField( headerStruct->extensionHeaders()()[i].header__name(), headerStruct->extensionHeaders()()[i].header__value(), buf );
    }
}
  //extra CRLF after header:
  buf.put_cs("\r\n");
  log_debug(tsp__RTSP__debugging,"RTSP_encodeHeader finished");
}

//=== Decode Header Fields: ====

//=======================================
// decodeHeaderField()
//=======================================
void decodeHeaderField(
    const char* headerName, 
    const char* headerValue, 
    HeaderStruct& headerStruct)
{
  bool processed = false;
  if(headerName[0]=='A')
  {
    if(!strcasecmp(headerName,"Accept"))               { headerStruct.accept()=headerValue; processed=true;}
    else if(!strcasecmp(headerName,"Accept-Encoding")) { headerStruct.acceptEncoding()=headerValue; processed=true;}
    else if(!strcasecmp(headerName,"Accept-Language")) { headerStruct.acceptLanguage()=headerValue; processed=true;}
    else if(!strcasecmp(headerName,"Allow"))           { headerStruct.allow()=headerValue; processed=true;}
    else if(!strcasecmp(headerName,"Authorization"))   { headerStruct.authorization()=headerValue; processed=true;}
    //:(
    else log_debug(tsp__RTSP__debugging,  "The following field is not processed yet: %s: %s>", headerName, headerValue);
  }
  else if(headerName[0]=='B')
  {
    // bandwidth
    if(!strcasecmp(headerName,"Bandwidth"))     { headerStruct.bandwidth()=headerValue;processed=true;}
    // blocksize   
    else if(!strcasecmp(headerName,"Blocksize")){ headerStruct.blocksize()=headerValue;processed=true;}
    
  }
  else if(headerName[0]=='C')
  {
    // cacheControl   
    if(!strcasecmp(headerName,"Cache-Control"))       { headerStruct.cacheControl()=headerValue;processed=true;}
    // conference
    else if(!strcasecmp(headerName,"conference"))      { headerStruct.conference()=headerValue; processed=true;}
    // connection     
    else if(!strcasecmp(headerName,"connection"))      { headerStruct.connection()=headerValue; processed=true;}
    // contentBase
    else if(!strcasecmp(headerName,"Content-Base"))     { headerStruct.contentBase()=headerValue; processed=true;}
    // contentEncoding
    else if(!strcasecmp(headerName,"Content-Encoding")) { headerStruct.contentEncoding()=headerValue; processed=true;}
    // contentLanguage
    else if(!strcasecmp(headerName,"Content-Language")) { headerStruct.contentLanguage()=headerValue; processed=true;}
    // contentLength
    else if(!strcasecmp(headerName,"Content-Length"))   { headerStruct.contentLength()=headerValue; processed=true;}
    // contentLocation
    else if(!strcasecmp(headerName,"Content-Location")) { headerStruct.contentLocation()=headerValue; processed=true;}
    // contentType    
    else if(!strcasecmp(headerName,"Content-Type"))     { headerStruct.contentType()=headerValue; processed=true;}
    // cSeq    
    else if(!strcasecmp(headerName,"CSeq"))             { headerStruct.cSeq()=headerValue; processed=true;}
    //:(
    else log_debug(tsp__RTSP__debugging,  "The following field is not processed yet: %s: %s>", headerName, headerValue);
  }//eof 'C'
  // date     
  else if(!strcasecmp(headerName,"Date")) { headerStruct.date()=headerValue; processed=true;}
  // expires     
  else if(!strcasecmp(headerName,"Expires")) { headerStruct.expires()=headerValue; processed=true;}
// fromField
  else if(!strcasecmp(headerName,"From")) { headerStruct.fromField()=headerValue; processed=true;}
// host
  else if(!strcasecmp(headerName,"Host")) { headerStruct.host()=headerValue; processed=true;}
// ifMatch
  else if(!strcasecmp(headerName,"If-Match")) { headerStruct.ifMatch()=headerValue; processed=true;}
// ifModifiedSince
  else if(!strcasecmp(headerName,"If-Modified-Since")) { headerStruct.ifModifiedSince()=headerValue; processed=true;}
// lastModified
  else if(!strcasecmp(headerName,"Last-Modified")) { headerStruct.lastModified()=headerValue; processed=true;}
// location       
  else if(!strcasecmp(headerName,"Location")) { headerStruct.location()=headerValue; processed=true;}
// proxyAuth
  else if(!strcasecmp(headerName,"Proxy-Authenticate")) { headerStruct.proxyAuth()=headerValue; processed=true;}
// proxyRequire
  else if(!strcasecmp(headerName,"Proxy-Require")) { headerStruct.proxyRequire()=headerValue; processed=true;}
// public
  else if(!strcasecmp(headerName,"Public")) { headerStruct.publicField()=headerValue; processed=true;}
  else if(headerName[0]=='R') {
    // range
    if(!strcasecmp(headerName,"Range")) { headerStruct.range()=headerValue; processed=true;}
    //RdtFeatureLevel:
    else if(!strcasecmp(headerName,"RdtFeatureLevel")) { headerStruct.rdtFeatureLevel()=headerValue; processed=true;}
    //RealChallenge1:
    else if(!strcasecmp(headerName,"RealChallenge1")) { headerStruct.realChallenge1()=headerValue; processed=true;}
    //reconnect
    else if(!strcasecmp(headerName,"Reconnect")) { headerStruct.reconnect()=headerValue; processed=true;}
    // referer
    else if(!strcasecmp(headerName,"Referer")) { headerStruct.referer()=headerValue; processed=true;}
    // retryAfter     
    else if(!strcasecmp(headerName,"Retry-After")) { headerStruct.retryAfter()=headerValue; processed=true;}
    // require        
    else if(!strcasecmp(headerName,"Require")) { headerStruct.require()=headerValue; processed=true;}
    else if(!strcasecmp(headerName,"Rtcp-Interval")) { headerStruct.rtcpInterval()=headerValue; processed=true;}
    // rtpInfo
    else if(!strcasecmp(headerName,"RTP-Info")) { headerStruct.rtpInfo()=headerValue; processed=true;}
  }
  else if(headerName[0]=='S') {
    // scale
    if(!strcasecmp(headerName,"Scale"))       { headerStruct.scale()=headerValue; processed=true;}
    // speed
    else if(!strcasecmp(headerName,"Speed"))  { headerStruct.speed()=headerValue; processed=true;}
    // server         
    else if(!strcasecmp(headerName,"Server")) { headerStruct.server()=headerValue; processed=true;}
    // session
    else if(!strcasecmp(headerName,"Session")){ headerStruct.session()=headerValue; processed=true;}
    //statsMask
    else if(!strcasecmp(headerName,"StatsMask")){ headerStruct.statsMask()=headerValue; processed=true;}
    //:(
    else log_debug(tsp__RTSP__debugging,  "The following field is not processed yet: %s: %s>", headerName, headerValue);
  }
   // timeStamp
  else if(!strcasecmp(headerName,"Timestamp")) { headerStruct.timeStamp()=headerValue; processed=true;}
  // transport
  else if(!strcasecmp(headerName,"Transport")) { headerStruct.transport()=headerValue; processed=true;}
  // unsupported
  else if(!strcasecmp(headerName,"Unsupported")) { headerStruct.unsupported()=headerValue; processed=true;}
  // userAgent      
  else if(!strcasecmp(headerName,"User-Agent")) { headerStruct.userAgent()=headerValue; processed=true;}
  // vary           
  else if(!strcasecmp(headerName,"Vary")) { headerStruct.vary()=headerValue; processed=true;}
  // via            
  else if(!strcasecmp(headerName,"Via")) { headerStruct.via()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"Vsrc")) { headerStruct.vsrc()=headerValue; processed=true;}
  // wwwAuth      
  else if(!strcasecmp(headerName,"WWW-Authenticate")) { headerStruct.wwwAuth()=headerValue; processed=true;}
  //xRealUsestrackid
  else if(!strcasecmp(headerName,"X-Real-Usestrackid")) { headerStruct.xRealUsestrackid()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-Vig-Bno")) { headerStruct.xVigBno()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-Vig-Msisdn")) { headerStruct.xVigMsisdn()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"x-retransmit")) { headerStruct.xRetransmit()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"x-dynamic-rate")) { headerStruct.xDynamicRate()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"x-transport-options")) { headerStruct.xTransportOptions()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"x-prebuffer")) { headerStruct.xPrebuffer()=headerValue; processed=true;}    
  else if(!strcasecmp(headerName,"X-Action")) { headerStruct.xAction()=headerValue; processed=true;}  
  else if(!strcasecmp(headerName,"X-EncodingFiles")) { headerStruct.xEncodingFiles()=headerValue; processed=true;}  
  else if(!strcasecmp(headerName,"X-UdpPipe")) { headerStruct.xUdpPipe()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-MbmsSync")) { headerStruct.xMbmsSync()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-Bandwidth")) { headerStruct.xBandwidth()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-Content")) { headerStruct.xContent()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-Fec")) { headerStruct.xFec()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-UserPlaneDest")) { headerStruct.xUserPlaneDest()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-FluteBitrate")) { headerStruct.xFluteBitrate()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-Tsi")) { headerStruct.xTsi()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-ContentFdtSendInterval")) { headerStruct.xContentFdtSendInterval()=headerValue; processed=true;}
  else if(!strcasecmp(headerName,"X-Reporting")) { headerStruct.xReporting()=headerValue; processed=true;}
                 
  //log_debug(tsp__RTSP__debugging,  "Value Processed: %i:>", processed);
  
  //if not process yet, process it as extension header:
  if(!processed)
  {
    log_debug(tsp__RTSP__debugging, "Decode extensionHeader follows:");
    if( headerStruct.extensionHeaders().ispresent()) {
      log_debug(tsp__RTSP__debugging, "Decode extensionHeader ispresent branch follows:");
      unsigned int size = headerStruct.extensionHeaders()().size_of();
      HeaderLine& tmp_0 = headerStruct.extensionHeaders()()[size];
      tmp_0.header__name()=headerName;
      tmp_0.header__value()=headerValue;
      //headerStruct.extensionHeaders()()[size].header__name()=headerName;
      //headerStruct.extensionHeaders()()[size].header__value()=headerValue;
      log_debug(tsp__RTSP__debugging,  "The following field is not processed yet: %s: %s>", headerName, headerValue);
    }
    else
    {
      log_debug(tsp__RTSP__debugging, "Decode extensionHeader not ispresent branch follows::");
      HeaderLine& tmp_0 = headerStruct.extensionHeaders()()[0];
      tmp_0.header__name()=headerName;
      tmp_0.header__value()=headerValue;
      //headerStruct.extensionHeaders()()[0].header__name()=headerName;
      //headerStruct.extensionHeaders()()[0].header__value()=headerName;
    }
  
  }
  else 
  {
    log_debug(tsp__RTSP__debugging, "field processed");
  }
  return;
}//decodeHeaderField

//from HTTPmsg__PortType:
//=======================================
//  Decoding_Params
//=======================================
typedef struct {
    bool non_persistent_connection;
    bool chunked_body;
    int content_length;
    bool error;
    bool isMessage;
} Decoding_Params;

//=======================================
//  get_line()
//=======================================
int get_line(TTCN_Buffer* buffer, CHARSTRING& to, const bool concatenate_header_lines)
{
    unsigned int i = 0;
    const unsigned char *cc_to = buffer->get_read_data();

    if(!buffer->get_read_len())
        return FALSE;

    while(1)
    {
        for( ; i < buffer->get_read_len() && cc_to[i] != '\0' && cc_to[i] != '\r' && cc_to[i] != '\n' ; i++);
        
        if(cc_to[i] == '\0')
        {
            to = CHARSTRING("");
            return FALSE;
        }
        else
        {
            if(cc_to[i] == '\n')
            {
              if(report_lf){
                switch( tsp__crlf__mode){
                  case  strict__crlf__mode::ERROR_:
                    return BUFFER_FAIL;
                    break;
                  case  strict__crlf__mode::WARNING__ONCE:
                    report_lf=false;
                    // no break
                  case strict__crlf__mode::WARNING:
                    TTCN_warning("Missing '\\r'.");
                    break;
                  default:
                    break;
                }
              }
              if(i > 0 && (i + 1) < buffer->get_read_len() && concatenate_header_lines && (cc_to[i+1] == ' ' || cc_to[i+1] == '\t'))
                    i += 1;
                  else
                  {
                      to = CHARSTRING(i, (const char*)cc_to);
                      buffer->set_pos(buffer->get_pos() + i + 1);
                      return i == 0 ? BUFFER_CRLF : TRUE;
                  }
            }
            else
            {
                if((i + 1) < buffer->get_read_len() && cc_to[i + 1] != '\n')
                  return BUFFER_FAIL;
                else if(i > 0 && (i + 2) < buffer->get_read_len() && concatenate_header_lines && (cc_to[i+2] == ' ' || cc_to[i+2] == '\t'))
                  i += 2;
                else
                {
                    to = CHARSTRING(i, (const char*)cc_to);
                    buffer->set_pos(buffer->get_pos() + i + 2);
                    return i == 0 ? BUFFER_CRLF : TRUE;
                }
            }
        }
    }
}

//=======================================
// log_to_hexa
//=======================================
void log_to_hexa(TTCN_Buffer* buffer)
{
    int len = buffer->get_read_len();
    const unsigned char* ptr = buffer->get_read_data();
    for(int i = buffer->get_pos(); i < len; i++)
    {
        TTCN_Logger::log_event(" %02X", ptr[i]);
    }
}


//=======================================
//  RTSP_decode_chunked_body
//=======================================
void RTSP_decode_chunked_body(TTCN_Buffer* buffer, OCTETSTRING& body, Decoding_Params& decoding_params,
    const bool debugging)
{
    OCTETSTRING chunk;
    CHARSTRING line;
    unsigned int chunk_size = 1;

    while(chunk_size > 0)
    {
        switch(get_line(buffer, line, false))
        {
            case TRUE:
                log_debug(tsp__RTSP__debugging, "line: <%s>", (const char*)line);
                if(sscanf((const char *)line, "%x", &chunk_size) != 1)
                {
                    log_debug(tsp__RTSP__debugging,  "No chunksize found");
                    body = body + OCTETSTRING(line.lengthof(), (const unsigned char*)(const char*)line);
                    chunk_size = 0;
                    decoding_params.error = TRUE;
                }
                else
                {
                    if(chunk_size == 0)
                    {
                        log_debug(tsp__RTSP__debugging, "chunk_size 0 -> closing chunk");
                        if(get_line(buffer, line, false) == BUFFER_CRLF)
                            log_debug(tsp__RTSP__debugging, "Trailing \\r\\n ok!");
                        else
                            TTCN_Logger::log(
                              TTCN_WARNING,
                              "Trailing \\r\\n after the closing chunk is not present, instead it is <%s>!", 
                              (const char*)line);
                    }
/*                    else if(chunk_size < 0) // never true
                    {
                        log_debug(tsp__RTSP__debugging, "chunk_size less than 0");
                        decoding_params.error = TRUE;
                        chunk_size = 0;
                    }*/
                    else // chunk_size > 0
                    {
                        log_debug(tsp__RTSP__debugging, "processing next chunk, size: %d", chunk_size);
                        if(buffer->get_read_len() < chunk_size)
                        {
                            log_debug(tsp__RTSP__debugging, "chunk size is greater than the buffer length, more data is needed");
                            decoding_params.isMessage = FALSE;
                            chunk_size = 0;
                        }
                    }
                }
                break;
            case FALSE:
                log_debug(tsp__RTSP__debugging, "buffer does not contain a whole line, more data is needed");
                decoding_params.isMessage = FALSE;
                chunk_size = 0;
                break;
            case BUFFER_CRLF:
                log_debug(tsp__RTSP__debugging, "beginning CRLF removed");
                continue;
            case BUFFER_FAIL:
                log_debug(tsp__RTSP__debugging, "BUFFER_FAIL");
                decoding_params.error = FALSE;
                chunk_size = 0;
                break;
            default:
                decoding_params.isMessage = FALSE;
                chunk_size = 0;
                log_debug(tsp__RTSP__debugging, "more data is needed");
        }
        
        body = body + OCTETSTRING(chunk_size, buffer->get_read_data());
        log_debug(tsp__RTSP__debugging, "pull %d bytes from %d", chunk_size, buffer->get_read_len());
        buffer->set_pos(buffer->get_pos() + chunk_size);
        // hack
        if(buffer->get_read_data()[0] == '\n')
        {
            TTCN_Logger::log(TTCN_WARNING, "hack: adjusted buffer position after the '\\n'");
            buffer->set_pos(buffer->get_pos() + 1);
        }
        log_debug(tsp__RTSP__debugging, "remaining data: <%s>, len: %d", (const char *)CHARSTRING(buffer->get_read_len(), (const char*)buffer->get_read_data()), buffer->get_read_len());
    }
}

//=======================================
//  RTSP_decodeHeader
//=======================================
void RTSP_decodeHeader(TTCN_Buffer* buffer, HeaderStruct& header, Decoding_Params& decoding_params,
    const bool debugging, const bool resp)
{
    CHARSTRING cstr;
    const char* separator;
    char* headerName = NULL;
//    bool length_received = false;
    
    for(int i = 0; ; i++)
    {
        switch(get_line(buffer, cstr, true))
        {
        case TRUE:
            {
                char h[cstr.lengthof() + 1];
                strcpy(h, (const char*)cstr);
                separator = strchr(h, ':');
                if(separator)
                {
                    headerName = (char*)Realloc(headerName, separator - h + 1);
                    strncpy(headerName, h, separator - h);
                    headerName[separator - h] = '\0';
                    
                    separator++; //first char of next token 
                    
                    //cut off leading spaces:
                    while(*separator && isspace(separator[0])) 
                        separator++;
                    
                    //cut off trailing spaces:
                    char* end = h + strlen(h);
                    while(isspace((end - 1)[0]))
                    {
                        end--;
                        *end = '\0';
                    }
                    //header[i] = HeaderLine(headerName, separator);
                    decodeHeaderField(headerName, separator, header);
                    log_debug(tsp__RTSP__debugging,  "+Header line processed: <%s: %s>", headerName, separator);

                    if(!strcasecmp(headerName, "Content-Length"))
                         { sscanf(separator, "%d", &decoding_params.content_length); /*length_received=true;*/}
                    else if(!strcasecmp(headerName, "Connection") && !strcasecmp(separator, "close"))
                        decoding_params.non_persistent_connection = TRUE;
                    else if(!strcasecmp(headerName, "Connection") && !strcasecmp(separator, "keep-alive"))
                        decoding_params.non_persistent_connection = FALSE;
                    else if(!strcasecmp(headerName, "Transfer-Encoding") && !strcasecmp(separator, "chunked"))
                        decoding_params.chunked_body = TRUE;

                }
                continue;
            }
        case BUFFER_FAIL:
            log_debug(debugging,  "BUFFER_FAIL in RTSP_decodeHeader!");
            log_debug(debugging,  "whole buffer now: <%s>", (const char*)buffer->get_data());
            log_to_hexa(buffer);
            decoding_params.error = TRUE;
        case FALSE:
            decoding_params.isMessage = FALSE;
        case BUFFER_CRLF:
            break;
        }
        break;
    }

    Free(headerName);
}

// //=======================================
// //  RTSP_decodeMethod //removed, use Method::enum_type Method::str_to_enum instead, see RTSP_Types.cc
// //=======================================


//=======================================
//  RTSP_decode_body
//=======================================
void RTSP_decode_body(TTCN_Buffer* buffer, OCTETSTRING& body, Decoding_Params& decoding_params, const bool connection_closed,
    const bool debugging)
{
    if(buffer->get_read_len() > 0)
        log_debug(tsp__RTSP__debugging, "Decoding body, buffer length: %d", buffer->get_read_len());
    
    if (decoding_params.chunked_body)
    {
        RTSP_decode_chunked_body(buffer, body, decoding_params, debugging);
        log_debug(tsp__RTSP__debugging, "--------- After chunked body decoding:");
        log_debug(tsp__RTSP__debugging, "--------- non_persistent_connection: %s",  decoding_params.non_persistent_connection ? "yes" : "no");
        log_debug(tsp__RTSP__debugging, "--------- chunked_body: %s",  decoding_params.chunked_body ? "yes" : "no");
        log_debug(tsp__RTSP__debugging, "--------- content_length: %d",  decoding_params.content_length);
        log_debug(tsp__RTSP__debugging, "--------- error: %s",  decoding_params.error ? "yes" : "no");
        log_debug(tsp__RTSP__debugging, "--------- isMessage: %s",  decoding_params.isMessage ? "yes" : "no");
        
    }
    else if(decoding_params.content_length >= 0)
    {
        log_debug(tsp__RTSP__debugging, "lengthof body: %d, content_length given: %d", buffer->get_read_len(), decoding_params.content_length);
        if(buffer->get_read_len() >= (unsigned)decoding_params.content_length)
        {
            body = OCTETSTRING(decoding_params.content_length, buffer->get_read_data());
            buffer->set_pos(buffer->get_pos() + decoding_params.content_length);
        }
        else
        {
            decoding_params.isMessage = FALSE;
            log_debug(tsp__RTSP__debugging, "The decoder's body length %d is less than the Content_length in the message header %d; The RTSP port is waiting for additional data.", buffer->get_read_len(), decoding_params.content_length);
            buffer->set_pos(buffer->get_pos() + buffer->get_read_len());
        }
    }
    else if(connection_closed)
    {
        if(buffer->get_read_len() >= 0)
        {
            body = OCTETSTRING(buffer->get_read_len(), buffer->get_read_data());
            buffer->set_pos(buffer->get_pos() + buffer->get_read_len());
        }
    } else {
            decoding_params.isMessage = FALSE;
            log_debug(tsp__RTSP__debugging, "The RTSP port is waiting for additional data.");
            buffer->set_pos(buffer->get_pos() + buffer->get_read_len());
    }
}


//=======================================
//  f_RTSP_decodeCommon
//=======================================
// returns with true if the buffer is not empty and it contain valid message
// Postcondition: if buffer contains valid message, msg will contain the first decoded RTSP message, the decoded part will be removed from the buffer
bool f_RTSP_decodeCommon( TTCN_Buffer* buffer, PDU__RTSP& msg, const bool connection_closed,
    const bool debugging)
{
    TTCN_Logger::log(TTCN_DEBUG, "starting f_RTSP_decodeCommon ");
    if(buffer->get_read_len() <= 0)
        return FALSE;
        
    buffer->rewind();
    
    Decoding_Params decoding_params;
    decoding_params.non_persistent_connection = FALSE;
    decoding_params.chunked_body = FALSE;
    decoding_params.content_length = -1;
    decoding_params.error = FALSE;
    decoding_params.isMessage = TRUE;
    
    if (TTCN_Logger::log_this_event(TTCN_DEBUG))
    {
      TTCN_Logger::log(TTCN_DEBUG, "DECODER: <%s>\n",
       (const char*)CHARSTRING(buffer->get_read_len(), 
       (const char*)buffer->get_read_data()));
    }

    CHARSTRING first;
    bool isResponse;

    // Decoding the first line

    switch(get_line(buffer, first, false))
    {
      case TRUE: // The first line is available
        {
            HeaderStruct header(c__emptyHeaderStruct);
            OCTETSTRING body=OCTETSTRING(0, (const unsigned char*)"");
            const char *cc_first = (const char *)first;
            //fprintf(stderr, "first: %s\n", cc_first);
            int version__major, version__minor, statusCode;

            char* method_name;
            char* pos = strchr(cc_first, ' ');
            if(pos == NULL)
            {
                TTCN_Logger::log(TTCN_DEBUG, "could not find space in the first line of message: <%s>", cc_first);
                decoding_params.isMessage = FALSE;
                decoding_params.error = TRUE;
                break;
            }
            method_name = (char*)Malloc(pos - cc_first + 1);
            strncpy(method_name, cc_first, pos - cc_first);
            method_name[pos - cc_first] = '\0';

            char* stext = (char*)Malloc(strlen(cc_first));

            TTCN_Logger::log(TTCN_DEBUG, "method_name: <%s>", method_name);
            if(strncasecmp(method_name, "RTSP/", 5) == 0)
            {
                // The first line contains a response like RTSP/1.0 200 OK
                isResponse = true;

                if(sscanf(cc_first, "RTSP/%d.%d %d %[^\r]", &version__major, &version__minor,
                          &statusCode, stext) != 4)
                {
                    decoding_params.isMessage = FALSE;
                    decoding_params.error = TRUE;
                    break;
                }
                if (version__minor != 0)
                    decoding_params.non_persistent_connection = TRUE;
            }
            else
            {
                isResponse = false;
                // The first line contains a request
                // like "DESCRIBE / RTSP/1.0"
                if(sscanf(pos + 1, "%s RTSP/%d.%d",
                          stext, &version__major, &version__minor ) != 3)
                {
                    decoding_params.isMessage = FALSE;
                    decoding_params.error = TRUE;
                    break;
                }
            }

            // Additional header lines
            TTCN_Logger::log(TTCN_DEBUG, "Decoding the header");
            RTSP_decodeHeader(buffer, header, decoding_params, debugging,isResponse);
            TTCN_Logger::log(TTCN_DEBUG, "Headers decoded. %s header.", decoding_params.isMessage ? "Valid" : "Invalid");

            if(isResponse && decoding_params.content_length==-1){
              if( (statusCode>99 && statusCode <200) || statusCode==204 || statusCode==304 ) decoding_params.content_length=0;
            }

            if(decoding_params.isMessage)
                RTSP_decode_body(buffer, body, decoding_params, connection_closed, debugging );

            if(decoding_params.isMessage)
            {
                TTCN_Logger::log(TTCN_DEBUG, "Message successfully decoded");
                bool foundBinaryCharacter = false;
                
                int len = body.lengthof();
                const unsigned char* ptr = (const unsigned char*)body;
                for(int i = 0; i < len && !foundBinaryCharacter; i++)
                {
                    if(!isascii(ptr[i]))
                        foundBinaryCharacter = true;
                }
                if(foundBinaryCharacter)
                    TTCN_Logger::log(TTCN_DEBUG, "Binary data found");
                if(isResponse)
                {
                    RTSPResponse& response = msg.response();
                    //response.client__id() = OMIT_VALUE;
                    response.statusLine().version().major_() = version__major;
                    response.statusLine().version().minor_() = version__minor;
                    response.statusLine().statusCode() = statusCode;
                    
                    if(strlen(stext) > 0)
                        response.statusLine().reasonPhrase() = CHARSTRING(stext);
                    else
                        response.statusLine().reasonPhrase() = "";
                    response.header() = header;
                    response.body() = body;
                }
                else //request:
                {
                    RTSPRequest& request = msg.request();
                    request.requestLine().method() = Method::str_to_enum(method_name); 
                    request.requestLine().uri() = CHARSTRING(stext); 
                    request.requestLine().version().major_() = version__major;
                    request.requestLine().version().minor_() = version__minor;
                    request.header() = header;
                    request.body() = body;
                }
            }
            Free(method_name);
            Free(stext);
        }
        break;
    case BUFFER_CRLF:
    case BUFFER_FAIL:
        decoding_params.error = TRUE;
    case FALSE:
        decoding_params.isMessage = FALSE;
    }

    if(decoding_params.error)
    {
        PDU__RTSP msg;
        if(buffer->get_read_len() > 0)
          msg.erronous__msg().msg() = (const char*)buffer->get_read_data();
        else
          msg.erronous__msg().msg() = "The previous message is erronous.";
        buffer->clear();
        decoding_params.isMessage = TRUE;
    }

    if(decoding_params.isMessage)
    {
        buffer->cut();
    }

    return decoding_params.isMessage;
}

INTEGER f__RTSP__getMsgLen(const OCTETSTRING& stream) {
  TTCN_Buffer *buffer = new TTCN_Buffer() ;
  buffer->put_os(stream);
  
  const unsigned char *cc_to = buffer->get_read_data();
  int buf_len = buffer->get_read_len();
  int content_length = 0;
  int length_until_body = 0;
  CHARSTRING line;
  char* separator;
  bool is_message = false;
  int length =-1;
  
  if(buf_len > 0)
  {
    buffer->rewind();

  
    //First line:
    if(get_line(buffer,line,false)!=TRUE) { delete buffer; return -1;}
    log_debug(tsp__RTSP__debugging,  "Line processed: <%s>", (const char*) line);
    
    //The other lines:
    while(true)
    {
      switch(get_line(buffer,line,false))
      {
        case TRUE:
          {
            log_debug(tsp__RTSP__debugging,  "TRUE:Line processed: <%s>", (const char*) line);
            char h[line.lengthof() + 1];
            strcpy(h, (const char*)line);
            separator=strchr(h, ':');
            *separator='\0';
            if(!strcasecmp(h,"Content-Length"))
            { 
              separator++;
              while(*separator && isspace(separator[0])) 
                        separator++;
              char* end = h + strlen(h);
              while(isspace((end - 1)[0]))
              {
                end--;
                *end = '\0';
              }
              log_debug(tsp__RTSP__debugging, "My content length:%s",separator);
              sscanf(separator,"%d",&content_length);
            }
            //else:go on
            continue;
          }
        case BUFFER_FAIL:
          {
            log_debug(tsp__RTSP__debugging, "BUFFER_FAIL in f__RTSP__getMsgLen!");
            log_debug(tsp__RTSP__debugging,  ">>>f__RTSP__getMsgLen:whole buffer now: <%s>", (const char*)buffer->get_read_data());
            break;
          }
        case FALSE:
            is_message = false;
            log_debug(tsp__RTSP__debugging,  ">>>FALSE reached");
            break;
        case BUFFER_CRLF:
            is_message = true;
            log_debug(tsp__RTSP__debugging,  ">>>BUFFER_CRLF reached f__RTSP__getMsgLen: whole buffer now: <%s>", (const char*)buffer->get_read_data());
            break;
      }
      break;
    }
    if(is_message) 
    {
       length_until_body= buffer->get_read_data()-cc_to;
       length= length_until_body+content_length;
       log_debug(tsp__RTSP__debugging, "Calculated length until body______________________________:<%d>",length_until_body);
       log_debug(tsp__RTSP__debugging, "Expected message length (first line+header+Content-Length):<%d>", length );
       log_debug(tsp__RTSP__debugging, "Buffer length_____________________________________________:<%d>",buf_len);
     }
     else
     {
       length=-1;
     }
  }
  delete buffer;
  return  length;
}

//=========================================================================
//==== Encoder-decoder Functions independent from sending and receiving:===
//=========================================================================

/*********************************************************
* Function: enc__PDU__RTSP
*
* Purpose:
*    To encode msg type of PDU__RTSP into OCTETSTRING
*
* References:
*   RFC 2326 :  Real Time Streaming Protocol (RTSP)
*
* Precondition:
*  msg is filled in properly
* Postcondition:
*  
*
* Parameters:
*  msg - the RTSP Message to be encoded
*  automaticContentLengthCalc - boolean parameter to calculate the Content Length automatically or not
* Return Value:
*   OCTETSTRING - the encoded message
* Detailed Comments:
*   -
*
*********************************************************/
OCTETSTRING enc__PDU__RTSP( const PDU__RTSP& msg,const BOOLEAN& automaticContentLengthCalc) 
{  
  log_debug(true, "enc__PDU__RTSP started");
  TTCN_Buffer buf;
  buf.clear();
  if( msg.get_selection() == PDU__RTSP::ALT_erronous__msg )
    buf.put_cs(msg.erronous__msg().msg());
  else
  {
    const OCTETSTRING* body = NULL;
    const HeaderStruct* headerStruct;
    if(msg.get_selection() == PDU__RTSP::ALT_request)
    { 
        log_debug(true, "enc__PDU__RTSP request is chosen");
        const RTSPRequest* request=&msg.request();
        log_debug(true, "enc__PDU__RTSP request ref copied into *request");
        headerStruct = &request->header();
        log_debug(true, "enc__PDU__RTSP body follows");
        body = &request->body();
        log_debug(true, "enc__PDU__RTSP RequestLine follows");
        //RequestLine:
        buf.put_cs(Method::enum_to_str(request->requestLine().method()));
        buf.put_c(' ');
        buf.put_cs(request->requestLine().uri());
        buf.put_cs(" RTSP/");
        buf.put_cs(int2str(request->requestLine().version().major_()));
        buf.put_c('.');
        buf.put_cs(int2str(request->requestLine().version().minor_()));
        buf.put_cs("\r\n");
    }
    else //if(msg.get_selection() == PDU__RTSP::ALT_response)
    {
        log_debug(true, "enc__PDU__RTSP response is chosen");
        const RTSPResponse* response = &msg.response();
        headerStruct = &response->header();
        body = &response->body();
        //StatusLine:
        buf.put_cs("RTSP/");
        buf.put_cs(int2str(response->statusLine().version().major_()));
        buf.put_c('.');
        buf.put_cs(int2str(response->statusLine().version().minor_()));
        buf.put_c(' ');
        buf.put_cs(int2str(response->statusLine().statusCode()));
        buf.put_c(' ');
        buf.put_cs(response->statusLine().reasonPhrase());
        buf.put_cs("\r\n");
    }
    log_debug(true, "enc__PDU__RTSP encodeHeader follows");
    RTSP_encodeHeader(headerStruct,buf,body->lengthof(),automaticContentLengthCalc); //with extra \r\n
    //Body
    log_debug(true, "enc__PDU__RTSP encoding body follows");
    if(body && body->lengthof() > 0)
    {
        buf.put_os(*body);
    }
  }
  return OCTETSTRING(buf.get_len(), buf.get_data());
}

/*********************************************************
* Function: dec__PDU__RTSP
*
* Purpose:
*    To decode msg type of OCTETSTRING into PDU__RTSP
*
* References:
*   RFC 2326 :  Real Time Streaming Protocol (RTSP)
*
* Precondition:
*  stream is filled in properly
* Postcondition:
*  -
*
* Parameters:
*  stream - the message to be decoded
*  msg    - reference to the record type of PDU__RTSP which will contain the decoded value if the return value less than the length of the original stream
* Return Value:
*   integer - the length of the remaining data which is not decoded yet.
* Detailed Comments:
*   If the full stream is decoded, the return value is -1
*   If nothing is decoded (decoding failed) the return value equals to the original length of the stream
*
*********************************************************/

INTEGER dec__PDU__RTSP(OCTETSTRING const& stream, PDU__RTSP& msg, const BOOLEAN& debugging=dec__PDU__RTSP_debugging_defval)
{
  TTCN_Logger::log(TTCN_DEBUG, "starting dec__PDU__RTSP");
  TTCN_Buffer *buf_p = new TTCN_Buffer() ;
  buf_p->put_os(stream);
  
  int buf_len = buf_p->get_read_len();
  if( buf_len > 0)
  {
      if(f_RTSP_decodeCommon(buf_p, msg, true, debugging))
      {
        log_debug(debugging,"","","dec__PDU__RTSP, after decoding:\nbuf_len: %d\nget_len: %d\nget_read_len:%d",
            buf_len, 
            buf_p->get_len(),
            buf_p->get_read_len());
        buf_len = buf_p->get_read_len(); //remaining data length
      }
      else
        buf_len = -1;
     
  } else buf_len = -1;
  
  delete buf_p;
  return buf_len;
}
  
}//namespace

