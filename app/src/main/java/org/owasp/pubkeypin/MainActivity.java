package org.owasp.pubkeypin;

import android.os.Bundle;
import android.app.Activity;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

public class MainActivity extends Activity {
	
	public static TextView m_secret;
	public static Button m_button;
	public static ProgressBar m_progress1, m_progress2;
	public static Activity m_this;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		m_this = this;
		
		m_secret = (TextView)findViewById(R.id.text_secret_data);
		assert(null != m_secret);
		
		m_button = (Button)findViewById(R.id.button_fetch);
		assert(null != m_button);
		
		m_progress1 = (ProgressBar)findViewById(R.id.progress_bar1);
		assert(null != m_progress1);
		if (null != MainActivity.m_progress1) {
			MainActivity.m_progress1.setVisibility(ProgressBar.INVISIBLE);
		}
		
		m_progress2 = (ProgressBar)findViewById(R.id.progress_bar2);
		assert(null != m_progress2);
		if (null != MainActivity.m_progress2) {
			MainActivity.m_progress2.setVisibility(ProgressBar.INVISIBLE);
		}
	}

	public void onFetchSecretClick(View v) {
		 new FetchSecretTask().execute();
	}
}