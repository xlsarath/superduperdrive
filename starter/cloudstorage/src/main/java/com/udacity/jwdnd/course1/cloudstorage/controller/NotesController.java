package com.udacity.jwdnd.course1.cloudstorage.controller;


import com.udacity.jwdnd.course1.cloudstorage.mapper.UserMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.Notes;
import com.udacity.jwdnd.course1.cloudstorage.model.User;
import com.udacity.jwdnd.course1.cloudstorage.services.NotesHandleService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class NotesController {

    private NotesHandleService notesHandleService;
    private UserMapper userMapper;

    public NotesController(NotesHandleService notesHandleService, UserMapper userMapper) {
        this.notesHandleService = notesHandleService;
        this.userMapper = userMapper;
    }

    @PostMapping(value="/createnote")
    public String createNotes(@ModelAttribute("SpringWeb") User user, Model model, Notes note){
        System.out.println("here");
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principal.toString();
        user = userMapper.getUser(username);
        System.out.println(username+" time to tprint");
        System.out.println(user.getUserId());
        if(note.getNoteid() == null) {
            System.out.println("create notes");
            if (notesHandleService.createNotes(note, user.getUserId()) > 0)
                model.addAttribute("successUpload", true);
        }
        else if(notesHandleService.updateNotes(note, user.getUserId()))
                model.addAttribute("successUpload",true);
        else
            model.addAttribute("error",true);
        return "result";
    }

    @GetMapping(value="/deletenote/{id}")
    public String deleteNotes(@PathVariable("id") Integer id,Model model){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = principal.toString();
        User user = userMapper.getUser(username);
        if(notesHandleService.deleteNote(id, user.getUserId()))
            model.addAttribute("successUpload",true);
        else
            model.addAttribute("error", true);
        return "result";
    }
}
