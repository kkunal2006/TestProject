package com.kunal.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;

import org.apache.xml.security.encryption.XMLCipher;
import org.w3c.dom.Document;

import com.kunal.demo.utilities.SecretKeyUtil;
import com.kunal.demo.utilities.XMLUtil;

@SpringBootApplication
public class TestProjectApplication {

	public static void main(String[] args) {
		SpringApplication.run(TestProjectApplication.class, args);
	}
	
	/*SecretKey secretKey = SecretKeyUtil.getSecretKey("AES");
	  Document document = XMLUtil.getDocument(xmlFile);

	  Document encryptedDoc = XMLUtil.encryptDocument(document, secretKey,
	    XMLCipher.AES_128);
	  XMLUtil.saveDocumentTo(encryptedDoc, encryptedFile);

	  Document decryptedDoc = XMLUtil.decryptDocument(encryptedDoc,
	    secretKey, XMLCipher.AES_128);
	  XMLUtil.saveDocumentTo(decryptedDoc, decryptedFile);*/
}
