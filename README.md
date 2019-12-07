# DetectCrossOriginMessaging

### About Cross origin messaging

PostMessage allows an object or string to be sent to another window or frame using JavaScript. The recipient window can either ignore the message or processes it with a function defined by the developer. Whilst no security or validation is provided out of the box, the inbound message event contains an “origin” property that can be used to validate the sending origin.

Cross-Origin communication via postMessage introduces a tainted data source that is difficult to identify using currently available tools.

In many cases, vulnerable code is introduced via third party libraries and therefore may undermine the security of an otherwise secure application.

If used carelessly, cross origin messaging can lead to DOM XSS and/or information leak.

### Common security vulnerabilities

#### DOM XSS

HTML5 postMessage introduces a new taint source in the form of the message payload (event.data). A DOM based XSS vulnerability occurs when the payload of a message event is handled in an unsafe way.

Common sinks:
- document.write(*input*)
- element.innerHTML = *input*
- location = *input*
- window.open(*input*)
- $(*input*)
- eval(*input*)
- ScriptElement.src = *input*
- ScriptElement.text = *input*

#### Broken origin validation:

Sometimes, regex are used to validate the origin domain.

If you encounter this types of checks, look for:
- unescaped dots: /^https*:\/\/(mail|www).google.com$/i -> https://mailxgoogle.com is allowed
- pattern that is not terminated with “$”: /^https*:\/\/(mail|www)\.google\.com/i -> https://mail.google.com.attacker.com is allowed

#### Information Leak

An information leak occurs when a page sends a postMessage to an attacker controlled domain.

This can happen in a number of ways, for example, the pages assumes that is being iframed by a trusted domain, and sends the message to the parent element.

```javascript
window.parent.postMessage(sensitiveData, "*");
```
All the attacker would need to do, is iframe the vulnerable page and receive the message.

### About this extension

This is a Burp extension which helps you find usages of cross origin messaging so that you can investigate the implementation closely and determine if it is secure or not.

![alt text](https://raw.githubusercontent.com/physics-sp/DetectCrossOriginMessaging/master/ejemplo.png)

### More information

To learn more about this type of vulnerability, I highly recommend reading [this amazing paper](https://www.sec-1.com/blog/wp-content/uploads/2016/08/Hunting-postMessage-Vulnerabilities.pdf).



