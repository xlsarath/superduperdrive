package com.udacity.jwdnd.course1.cloudstorage.controller;

import com.udacity.jwdnd.course1.cloudstorage.mapper.UserMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.File;
import com.udacity.jwdnd.course1.cloudstorage.model.User;
import com.udacity.jwdnd.course1.cloudstorage.services.FileHandleService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

@Controller
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

    @GetMapping(value="/downloadfile/{id}")
    public void downloadFile(
            @PathVariable("id") int fileid,
            HttpServletResponse response) {
        try {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            User user = userService.getUser(principal.toString());
            File file = fileHandleService.getFile(fileid,user.getUserId());
            org.apache.commons.io.IOUtils.copy(new ByteArrayInputStream(file.getFiledata()), response.getOutputStream());
            response.flushBuffer();
        } catch (IOException ex) {
            //log.info("Error writing file to output stream. Filename was '{}'", fileName, ex);
            throw new RuntimeException("IOError writing file to output stream");
        }

    }

    @GetMapping(value="/deletefile/{id}")
    public String deleteFile(@PathVariable("id") int id, Model model){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = userService.getUser(principal.toString());
        if(fileHandleService.deleteFile(user.getUserId(), id))
            model.addAttribute("successDelete", true);
        else
            model.addAttribute("errorDelete",true);
        return "result";
    }

    @PostMapping(value="/upload")
    private String commitUpload(@ModelAttribute("SpringWeb") User user,  MultipartFile fileUpload, Model model) throws IOException {
       // User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
      //  System.out.println("u r inside commitupload");
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principal.toString();
      //  System.out.println(username+" time to tprint");
        user = userService.getUser(username);
        //System.out.println(" username "+username+" "+user.getUserId());
      //  User user = (User) authentication.getPrincipal();
        if(!fileUpload.isEmpty()) {
          //  System.out.println(fileUpload.getName()+" "+fileUpload.getSize());
            if(!checkFileAvailability(fileUpload.getOriginalFilename(), user.getUserId())){
                model.addAttribute("fileexistserror", true);
                return "result";
                    }
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

    private boolean checkFileAvailability(String originalFilename, Integer userId) {
        List<File> ls = fileHandleService.getFiles(userId);
        boolean filenameExists = true;
        for(File eachFile : ls){
            if(eachFile.getFilename().equalsIgnoreCase(originalFilename))
                filenameExists = false;
        }
        return filenameExists;
    }
}
