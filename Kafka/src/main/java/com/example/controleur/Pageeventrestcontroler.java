package com.example.controleur;

import java.util.Date;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.example.entities.PageEvent;
@Component
public class Pageeventrestcontroler {
	@Autowired
	private StreamBridge streambridge;
	@GetMapping("/publish/{topic}/{name}")
	public PageEvent publish(@PathVariable String topic,@PathVariable String name) {
		PageEvent pageevent=new PageEvent(name,Math.random()>0.5?"u1":"u2",new Date(),new Random().nextInt(800));
		
		streambridge.send(topic, pageevent);
		return pageevent;
	}

}
