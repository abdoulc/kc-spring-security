package com.codewithabdel.springsecurityudemy.repository;

import com.codewithabdel.springsecurityudemy.entity.Contact;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface ContactRepository extends CrudRepository<Contact, Long> {
	
	
}
