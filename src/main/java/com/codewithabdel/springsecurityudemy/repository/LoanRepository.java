package com.codewithabdel.springsecurityudemy.repository;

import java.util.List;

import com.codewithabdel.springsecurityudemy.entity.Loans;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;


@Repository
public interface LoanRepository extends CrudRepository<Loans, Long> {
	@PreAuthorize("hasRole(USER)")
	List<Loans> findByCustomerIdOrderByStartDtDesc(int customerId);

}
