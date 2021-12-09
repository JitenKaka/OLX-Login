package com.olx.actuator;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.actuate.info.Info.Builder;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

@Component
public class CustomInfoIndicator implements  InfoContributor{

	ApplicationContext applicationContext;
	@Override
	public void contribute(Builder builder) {
		// TODO Auto-generated method stub
		Map<String, Integer> userDetails = new HashMap<>();
		 userDetails.put("Total registerd users Count", 100);
        userDetails.put("Active login Users Count ", 50);
        userDetails.put("Inactive", 50);

        builder.withDetail("users", userDetails);
		
	}

}
