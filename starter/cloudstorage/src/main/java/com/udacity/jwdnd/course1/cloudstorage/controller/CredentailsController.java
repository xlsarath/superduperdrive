package com.udacity.jwdnd.course1.cloudstorage.controller;

import com.udacity.jwdnd.course1.cloudstorage.mapper.UserMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.Credential;
import com.udacity.jwdnd.course1.cloudstorage.model.User;
import com.udacity.jwdnd.course1.cloudstorage.services.CredentialHandleService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class CredentailsController {

    private CredentialHandleService credentialHandleService;
    private UserMapper userMapper;

    public CredentailsController(CredentialHandleService credentialHandleService, UserMapper userMapper) {
        this.credentialHandleService = credentialHandleService;
        this.userMapper = userMapper;
    }


    @PostMapping(value="/addcredential")
    public String addCredentail(@ModelAttribute("SpringWeb") User user, Model model, Credential credential){

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principal.toString();
        user = userMapper.getUser(username);
        if(credential.getCredentialid() == null){
            if(credentialHandleService.insertCredentail(credential, user.getUserId()) > 0);
                    model.addAttribute("successUpload",true);
        } else if (credentialHandleService.updateCredentail(credential,user.getUserId()))
                    model.addAttribute("successUpload",true);
        else
            model.addAttribute("error",true);
        return "result";
    }

    @GetMapping(value = "/deletecredential/{id}")
    public String deleteCredentail(@PathVariable("id") Integer id, Model model){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principal.toString();
        User user = userMapper.getUser(username);
        if(credentialHandleService.deleteCredentail(id,user.getUserId()))
                model.addAttribute("successUpload",true);
        else
            model.addAttribute("error",true);
        return "result";
    }
}
