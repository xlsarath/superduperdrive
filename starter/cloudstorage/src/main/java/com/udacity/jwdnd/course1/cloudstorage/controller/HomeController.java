package com.udacity.jwdnd.course1.cloudstorage.controller;

import com.udacity.jwdnd.course1.cloudstorage.model.File;
import com.udacity.jwdnd.course1.cloudstorage.model.User;
import com.udacity.jwdnd.course1.cloudstorage.services.FileHandleService;
import com.udacity.jwdnd.course1.cloudstorage.services.UserService;
import org.mybatis.logging.Logger;
import org.mybatis.logging.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping(value = { "/", "/home" })
public class HomeController {

    private Logger logger = LoggerFactory.getLogger(HomeController.class);

    private FileHandleService fileHandleService;
    private UserService userService;

    public HomeController(FileHandleService fileHandleService, UserService userService) {
        this.fileHandleService = fileHandleService;
        this.userService = userService;
    }

    @GetMapping()
    public  String  getHomePage(Authentication authentication, Model model) throws Exception {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
      //  User user = (User) authentication.getPrincipal();

       // ModelAndView mv = new ModelAndView("home");
       // mv.addObject("files", fileHandleService.getAllFiles(user.getUserId()));
        //User user = (User) session.getAttribute("user");

        if (principal instanceof User) {
            String username = ((User)principal).getUsername();
            User user = userService.getUser(username);
            model.addAttribute("files", fileHandleService.getFiles(user.getUserId()));
        } else {
            String username = principal.toString();
            User user = userService.getUser(username);
            System.out.println(" username "+username+" "+user.getUserId());
            if(fileHandleService.getFiles(user.getUserId()) != null){
                List<File> ls = fileHandleService.getFiles(user.getUserId());
                for(File file : ls){
                    System.out.println(file.getFileid());
                }
                model.addAttribute("files", fileHandleService.getFiles(user.getUserId()));

            }
            model.addAttribute("user",user);
        }
        return "home";
    }

}
