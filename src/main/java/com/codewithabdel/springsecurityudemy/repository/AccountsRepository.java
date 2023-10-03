package com.codewithabdel.springsecurityudemy.repository;

import com.codewithabdel.springsecurityudemy.entity.Accounts;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface AccountsRepository extends CrudRepository<Accounts, Long> {
	
	Accounts findByCustomerId(int customerId);

}
