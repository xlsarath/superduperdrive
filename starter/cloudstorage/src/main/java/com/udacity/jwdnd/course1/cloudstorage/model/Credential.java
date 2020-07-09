package com.udacity.jwdnd.course1.cloudstorage.model;

public class Credential {

    public Credential(){
    }

    public Integer getCredentialid() {
        return credentialid;
    }

    public void setCredentialid(Integer credentialid) {
        this.credentialid = credentialid;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }


    public Integer getUserid() {
        return userid;
    }

    public void setUserid(Integer userid) {
        this.userid = userid;
    }

    public Integer credentialid;

    public Credential(String url, String username, String key, String password, Integer userid) {
        this.url = url;
        this.username = username;
        this.key = key;
        this.password = password;
        this.userid = userid;
    }

    public String url;
    public String username;
    public String key;
    public String password;

    public String getEncpassword() {
        return password;
    }

    public void setEncpassword(String encpassword) {
        this.password = encpassword;
    }

    public String getDecpassword() {
        return decpassword;
    }

    public void setDecpassword(String decpassword) {
        this.decpassword = decpassword;
    }

    private String decpassword;
    private Integer userid ;

}
