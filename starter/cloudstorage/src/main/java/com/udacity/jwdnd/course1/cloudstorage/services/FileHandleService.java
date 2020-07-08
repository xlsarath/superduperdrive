package com.udacity.jwdnd.course1.cloudstorage.services;

import com.udacity.jwdnd.course1.cloudstorage.mapper.FilehandleMapper;
import com.udacity.jwdnd.course1.cloudstorage.model.File;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@Service
public class FileHandleService {

    private FilehandleMapper filehandleMapper;

    public FileHandleService(FilehandleMapper filehandleMapper) {
        this.filehandleMapper = filehandleMapper;
    }

    public List<File> getFiles(Integer userId){
        return  filehandleMapper.getFilesByUserId(userId);
    }

    public List<File> getAllFiles(int userId) throws Exception {
        return filehandleMapper.getFilesByUserId(userId);
       // return files.stream().map(this::getResponseFile).collect(Collectors.toList());
    }

    public int addFile(MultipartFile multipartFile, Integer userId) throws IOException {
        if(multipartFile != null) {
            System.out.println(" file stored");
            File file = new File(multipartFile.getName(), multipartFile.getContentType(), multipartFile.getSize(), userId, multipartFile.getBytes());

            return filehandleMapper.insert(file);
        } else
       // return filehandleMapper.insert(new Files(null, multipartFile.getName(), multipartFile.getContentType(), multipartFile.getSize(), userId, multipartFile.getBytes()));
        return 0;
    }


}
