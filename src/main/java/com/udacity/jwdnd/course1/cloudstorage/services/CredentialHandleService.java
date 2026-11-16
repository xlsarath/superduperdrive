package com.udacity.jwdnd.course1.cloudstorage.services;

import com.udacity.jwdnd.course1.cloudstorage.mapper.CredentialMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.Credential;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class CredentialHandleService {

        private CredentialMapper credentialMapper;
        private  EncryptionService encryptionService;

    public CredentialHandleService(CredentialMapper credentialMapper, EncryptionService encryptionService) {
        this.credentialMapper = credentialMapper;
        this.encryptionService = encryptionService;
    }

    public List<Credential> getCredentails(Integer userId) {
            List<Credential> allCredentialsOfUser = credentialMapper.getAllCredentials(userId);
            if(allCredentialsOfUser == null) return new ArrayList<>();
            for(Credential eachCredential: allCredentialsOfUser){
                    eachCredential.setDecpassword(encryptionService.decryptValue(eachCredential.getEncpassword(),eachCredential.getKey()));
            }
            return allCredentialsOfUser;
    }

    public int insertCredentail(Credential credential, Integer userId) {

        if (credential.getKey() == null) {
            SecureRandom random = new SecureRandom();
            byte[] key = new byte[16];
            random.nextBytes(key);
            credential.setKey(Base64.getEncoder().encodeToString(key));
        }
        System.out.println(credential.getDecpassword()+" <-- password and key -->"+credential.getKey());
        credential.setEncpassword(encryptionService.encryptValue(credential.getDecpassword(), credential.getKey()));
        System.out.println("post encrypton : "+credential.getDecpassword()+" and "+credential.getEncpassword());
        return credentialMapper.insert(credential,userId);
    }

    public boolean updateCredentail(Credential credential, Integer userId) {
        if(credential.getKey()==null){
            SecureRandom random = new SecureRandom();
            byte[] key = new byte[16];
            random.nextBytes(key);
            credential.setKey(Base64.getEncoder().encodeToString(key));
        }
        credential.setEncpassword(encryptionService.encryptValue(credential.getDecpassword(), credential.getKey()));
        return credentialMapper.update(credential,userId);
    }

    public boolean deleteCredentail(Integer id, Integer userid) {
        return credentialMapper.delete(id,userid);
    }
}
