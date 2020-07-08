package com.udacity.jwdnd.course1.cloudstorage.controller;

import com.udacity.jwdnd.course1.cloudstorage.mapper.UserMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.User;
import com.udacity.jwdnd.course1.cloudstorage.services.FileHandleService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Controller
@RequestMapping("/upload")
public class FilehandleController {

    private FileHandleService fileHandleService;
    private UserMapper userService;


    public FilehandleController(FileHandleService fileHandleService, UserMapper userService) {
        this.fileHandleService = fileHandleService;
        this.userService = userService;
    }


    @GetMapping()
    public String fileView(){
        return "home";
    }


    @PostMapping()
    private String commitUpload(@ModelAttribute("SpringWeb") User user,  MultipartFile fileUpload, Model model) throws IOException {
       // User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        System.out.println("u r inside commitupload");
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principal.toString();
        System.out.println(username+" time to tprint");
        user = userService.getUser(username);
        System.out.println(" username "+username+" "+user.getUserId());
      //  User user = (User) authentication.getPrincipal();
        if(!fileUpload.isEmpty()) {
            fileHandleService.addFile(fileUpload, user.getUserId());
            model.addAttribute("successUpload", true);
            // model.addAttribute("files", fileHandleService.getFiles(user.getUserId()));
            return "result";
        }
        else {
            model.addAttribute("error", true);
            return "result";
        }
    }
}
