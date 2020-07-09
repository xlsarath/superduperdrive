package com.udacity.jwdnd.course1.cloudstorage.services;


import com.udacity.jwdnd.course1.cloudstorage.mapper.NotesMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.Notes;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NotesHandleService {

    private NotesMapper notesMapper;

    public NotesHandleService(NotesMapper notesMapper) {
        this.notesMapper = notesMapper;
    }


    public int createNotes(Notes note, Integer userId) {
        return notesMapper.insert(note,userId);
    }

    public boolean updateNotes(Notes note, Integer userId) {
        return notesMapper.updateNote(note,userId);
    }

    public boolean deleteNote(Integer id, Integer userId) {
        return notesMapper.deleteNote(id,userId);
    }

    public List<Notes> getNotes(Integer userId) {
        return notesMapper.getNotesListByUserId(userId);
    }
}
