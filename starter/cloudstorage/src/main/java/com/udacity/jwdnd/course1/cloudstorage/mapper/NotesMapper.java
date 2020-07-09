package com.udacity.jwdnd.course1.cloudstorage.mapper;

import com.udacity.jwdnd.course1.cloudstorage.model.Notes;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface NotesMapper {

    @Select("SECLET * FROM notes")
    List<Notes> getAllNotes();

    @Insert("INSERT INTO notes (notetitle, notedescription, userid) VALUES (#{note.notetitle}, #{note.notedescription}, #{userid})")
    int insert(@Param("note") Notes note, Integer userid);

    @Select("SELECT * FROM notes WHERE noteid = #{noteid} and userid = #{userid}")
    Notes getNotesByNoteId(int noteid,Integer userid);

    @Select("SELECT * FROM notes WHERE userid = #{userid}")
    List<Notes> getNotesListByUserId(Integer userid);

    @Delete("DELETE FROM notes WHERE noteid = #{noteid} and userid = #{userid}")
    boolean deleteNote(Integer noteid, Integer userid);

    @Update("UPDATE notes SET notetitle = #{note.notetitle}, notedescription = #{note.notedescription} WHERE noteid = #{note.noteid} AND userid = #{userid}")
    boolean updateNote(@Param("note")Notes note, Integer userid);

}
