<?php
/*
Plugin Name: Threat Scan Plugin
Plugin URI: http://www.BlogsEye.com/
Description: A simple scan of the Wordpress Content and Database looking for possible threats.
Version: 0.9
Author: Keith P. Graham
Author URI: http://www.BlogsEye.com/

This software is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/


add_action( 'admin_menu', 'kpg_threat_scan_admin' );
	
function kpg_threat_scan_admin() {
   add_options_page('Threat Scan', 'Threat Scan', 'manage_options', __FILE__,'kpg_threat_scan_options');
}
function kpg_threat_scan_options() {
	// scan db completely
	
	// need the prefix for these table: posts, links, comments, users
	global $wpdb;
	global $wp_query;
	$pre=$wpdb->prefix;
	?>
	<h2>Threat Scan</h2>
	<p>This is a very simple threat scan that looks for things out of place in the content directory as well as the database.</p>
	<p>It searches PHP files for the occurrence of the eval() function, which, although a valuable part of PHP is also the door that hackers use in order to infect systems. The eval() function is avoided by many programmers unless there is a real need. It is sometimes used by hackers to hide their malicious code or to inject future threats into infected systems. If you find a theme or a plugin that uses the eval() function it is safer to delete it and ask the author to provide a new version that does not use this function.</p>
	<p>When you scan your system you undoubtedly see the eval used in javascript because it is used in the javascript AJAX and JSON functionality. The appearance of eval in these cases does not mean that there is a possible threat. It just means that you should inspect the code to make sure that it is in a javascript section and not native PHP.</p>
	<p>The plugin continues its scan by checking the database tables for javascript or html where it should not be found.</p>
	<p>Normally, javascript is common in the post body, but if the script tag is found in a title or a text field where it does not belong it is probably because the script is hiding something, such as a hidden admin user, so that the normal administration pages do not show bad records. The scan looks for this and displays the table and record number where it believes there is something hinky.</p>
	<p>The scan continues looking in the database for certain html in places where it does not belong. Recent threats have been putting html into fields in the options table so that users will be sent to malicious sites. The presence of html in options values is suspect and should be checked.</p>
	<p>The options table will have things placed there by plugins so it is difficult to tell if scripts, iframes, and other html tags are a threat. They will be reported, but they should be checked before deleting the entries.</p>
	<p>This plugin is just a simple scan and does not try to fix any problems. It will show things that may not be threats, but should be checked. If anything shows up you, should try to repair the damage or hire someone to do it. I am not a security expert, but a programmer who discovered these types of things in a friend's blog. After many hours of checking I was able to fix the problem, but a professional could have done it faster and easier, although they would have charged for it.</p>
	<p>You probably do not have a backup to your blog, so if this scan shows you are clean; your next step is to install one of the plugins that does regular backups of your system. Next make sure you have the latest Wordpress version.</p>
	<p>If you think you have problems, the first thing to do is change your user id and password. Next make a backup of the infected system. Any repairs to Wordpress might delete important data so you might lose posts, and the backup will help you recover missing posts.</p>
	<p>The next step is to install the latest version of Wordpress. The new versions usually have fixes for older threats.</p>
	<p>You may want to export your Wordpress posts, make a new clean installation of Wordpress, and then import the old posts.</p>
	<p>If this doesn't work it is time to get a pro involved.<p>
	<h3>A clean scan does not mean you are safe. Please do Backups and keep your installation up to date!</h3>

	<hr/>
	
		<?php

/*
posts: ID: post_author, post_title, post_name, guid, post_mime_type, post_content
comments: comment_ID: author_url, comment_agent, comment_author, comment_email, comment_content
links: links_id: link_url, link_image, link_description, link_notes, link_rss
options: option_id option_value, option_name
postmeta: met_id: meta_key, meta_value
terms: term_id, name, slug
usermeta: umeta_id: meta_key, meta_value
users: ID: user_login,user_nicename, user_email, user_url, display_name


*/

// lets try the posts. Looking for script tags in data
		echo "<br/><br/>Testing Posts<br/>";
$ptab=$pre.'posts';
$sql= "select ID
from $ptab where 
INSTR(LCASE(post_author), '<script') +
INSTR(LCASE(post_title), '<script') +
INSTR(LCASE(post_name), '<script') +
INSTR(LCASE(guid), '<script') +
INSTR(post_author, 'eval(') +
INSTR(post_title, 'eval(') +
INSTR(post_name, 'eval(') +
INSTR(guid, 'eval(') +
INSTR(post_content, 'eval(') +
INSTR(post_content, 'document.write(unescape(') +
INSTR(post_content, 'try{window.onload') +
INSTR(post_content, 'setAttribute(\'src\'') +
INSTR(LCASE(post_mime_type), 'script') >0
";
//echo " <br/> $sql <br/>";
	$myrows = $wpdb->get_results( $sql );
	if ($myrows) {
		foreach ($myrows as $myrow) {
			echo "found possible problems in post ID: ". $myrow->ID.'<br/>';
		}
	} else {
		echo "<br/>nothing found in posts<br/>";
	}
	echo "<hr/>";
//comments: comment_ID: author_url, comment_agent, comment_author, comment_email
$ptab=$pre.'comments';
		echo "<br/><br/>Testing Comments<br/>";
	$sql="select comment_ID
from $ptab where 
INSTR(LCASE(comment_author_url), '<script') +
INSTR(LCASE(comment_agent), '<script') +
INSTR(LCASE(comment_author), '<script') +
INSTR(LCASE(comment_author_email), '<script') +
INSTR(comment_author_url, 'eval(') +
INSTR(comment_agent, 'eval(') +
INSTR(comment_author, 'eval(') +
INSTR(comment_author_email, 'eval(') +
INSTR(comment_content, '<script') +
INSTR(comment_content, 'eval(') +
INSTR(comment_content, 'document.write(unescape(') +
INSTR(comment_content, 'try{window.onload') +
INSTR(comment_content, 'setAttribute(\'src\'') +
INSTR(LCASE(comment_author_url), 'javascript:') >0
";
	$myrows = $wpdb->get_results( $sql );
	if ($myrows) {
		foreach ($myrows as $myrow) {
			echo "found possible problems in comment ID". $myrow->comment_ID.'<br/>';
		}
	} else {
		echo "<br/>nothing found in Comments<br/>";
	}
	echo "<hr/>";
// links: links_id: link_url, link_image, link_description, link_notes, link_rss
$ptab=$pre.'links';
		echo "<br/><br/>Testing Links<br/>";
	$sql="select link_ID
from $ptab where 
INSTR(LCASE(link_url), '<script') +
INSTR(LCASE(link_image), '<script') +
INSTR(LCASE(link_description), '<script') +
INSTR(LCASE(link_notes), '<script') +
INSTR(LCASE(link_rss), '<script') +
INSTR(link_url, 'eval(') +
INSTR(link_image, 'eval(') +
INSTR(link_description, 'eval(') +
INSTR(link_notes, 'eval(') +
INSTR(link_rss, 'eval(') +
INSTR(LCASE(link_url), 'javascript:') >0
";

	$myrows = $wpdb->get_results( $sql );
	if ($myrows) {
		foreach ($myrows as $myrow) {
			echo "found possible problems in links ID:". $myrow->link_ID.'<br/>';
		}
	} else {
		echo "<br/>nothing found in Links<br/>";
	}
	echo "<hr/>";

//users: ID: user_login,user_nicename, user_email, user_url, display_name
$ptab=$pre.'users';
 echo "<br/><br/>Testing Users<br/>";
	$sql="select ID
from $ptab where 
INSTR(LCASE(user_login), '<script') +
INSTR(LCASE(user_nicename), '<script') +
INSTR(LCASE(user_email), '<script') +
INSTR(LCASE(user_url), '<script') +
INSTR(LCASE(display_name), '<script') +
INSTR(user_login, 'eval(') +
INSTR(user_nicename, 'eval(') +
INSTR(user_email, 'eval(') +
INSTR(user_url, 'eval(') +
INSTR(display_name, 'eval(') +
INSTR(LCASE(user_url), 'javascript:') +
INSTR(LCASE(user_email), 'javascript:')>0
";
	$myrows = $wpdb->get_results( $sql );
	if ($myrows) {
		foreach ($myrows as $myrow) {
			echo "found possible problems in Users ID:". $myrow->ID.'<br/>';
		}
	} else {
		echo "<br/>nothing found in Users<br/>";
	}
echo "<hr/>";

//options: option_id option_value, option_name
// I may have to update this as new websites show up
$ptab=$pre.'options';
 echo "<br/><br/>Testing Options table for html<br/>";
	$sql="select option_id
from $ptab where 
INSTR(LCASE(option_value), '<script') +
INSTR(LCASE(option_value), 'display:none') +
INSTR(LCASE(option_value), 'networkads') +
INSTR(option_value, 'eval(') +
INSTR(LCASE(option_value), 'javascript:') >0
";
	$myrows = $wpdb->get_results( $sql );
	if ($myrows) {
		foreach ($myrows as $myrow) {
			echo "found possible problems in Options option_id:". $myrow->option_id.'<br/>';
		}
	} else {
		echo "<br/>nothing found in Options<br/>";
	}
echo "<hr/>";
echo "<h3>Scanning Themes and Plugins for eval</h3>";

kpg_scan_for_eval();

?>

<hr/>
<h3>If you like this plugin, why not try out these other interesting plugins.</h3>
<?php
// list of plugins
$p=array(
"facebook-open-graph-widget"=>"The easiest way to add a Facebook Like buttons to your blog' sidebar",
"threat-scan-plugin"=>"Check your blog for virus, trojans, malicious software and other threats",
"open-in-new-window-plugin"=>"Keep your surfers. Open all external links in a new window",
"youtube-poster-plugin"=>"Automagically add YouTube videos as posts. All from inside the plugin. Painless, no heavy lifting.",
"permalink-finder"=>"Never get a 404 again. If you have restructured or moved your blog, this plugin will find the right post or page every time",
);
  $f=$_SERVER["REQUEST_URI"];
  // get the php out
  $ff=explode('page=',$f);
  $f=$ff[1];
  $ff=explode('/',$f);
  $f=$ff[0];
  foreach ($p as $key=>$data) {
	if ($f!=$key) { 
	$kk=urlencode($key);
		?><p>&bull;<span style="font-weight:bold;"> <?PHP echo $key ?>: </span> <a href="plugin-install.php?tab=plugin-information&plugin=<?PHP echo $kk ?>&TB_iframe=true&width=640&height=669">Install Plugin</a> - <span style="font-style:italic;font-weight:bold;"><?PHP echo $data ?></span></p><?PHP 
	}
  }






} // end of function


//
	


	//add_action( 'plugins_loaded', 'kpg_threat_scan' );
	// don't need no stinking action - only used in settings
function kpg_scan_for_eval() {
	// scan content completely
	// WP_CONTENT_DIR is supposed to have the content dir
	$phparray=array();
	$phparray=kpg_scan_for_eval_recurse(WP_CONTENT_DIR,$phparray);
	// phparray should have a list of all of the PHP files
	$disp=false;
    echo "Files: <ol>";
	for ($j=0;$j<count($phparray);$j++) {
	    $ansa=kpg_look_in_file($phparray[$j]);
		if (count($ansa)>0) {
			$disp=true;
			echo "<li>".$phparray[$j]." <br/> ";
			for ($k=0;$k<count($ansa);$k++) {
				echo htmlentities($ansa[$k])." <br/>"; 
			}
			echo "</li>";
		}
	}
	echo "</ol>";
    if ($disp) {
	?>
	<h3>Possible problems found!</h3>
	<p>Although there are legitimate reasons for using the eval function, and javascript uses it frequently,
	finding eval in PHP code is in the very least bad practice, and the worst is used to hide malicious code. </p>
	<p>Your code could contain 'eval', or 'document.write(unescape(' or 'try{window.onload' or setAttribute('src'. These are markers for problems such as sql injection or cross-browser javascript.
	<?php
	
	} else {
	?>
	<h3>No problems found!</h3>
	<p>It appears tha there are no eval or suspicious javascript functions in the code in your wp-content directory. That does not mean that you are safe, only that a threat may be well hidden.</p>
	<?php	
	}

} // end of function

// recursive walk of directory structure.
function kpg_scan_for_eval_recurse($dir,$phparray) {
	if (!is_dir($dir))  return $phparray;

     if ($dh = opendir($dir)) {
        while (($file = readdir($dh)) !== false) {
		    if (is_dir($dir .'/'. $file)) {
				if ($file!='.' && $file!='..' ) {
					$phparray=kpg_scan_for_eval_recurse($dir .'/'. $file,$phparray);
				}
			} else if ( strpos($file,'.php')>0 ) {
				$phparray[count($phparray)]=$dir .'/'. $file;
			} else {
				//echo "can't find .php in $file <br/>";
			}
        }
        closedir($dh);
    }
	return $phparray;

}	
function kpg_look_in_file($file) {
	$handle=fopen($file,'r');
	$ansa=array();
	$n=0;
	$idx=0;
	if (strpos($file,'threat-scan')>0) return $ansa;
	while (!feof($handle)) {
		$line=fgets($handle);
		$n++;
		if (!(strpos($line,'eval(')===false)) {
			// bad boy
			$ansa[$idx]=$n.': '.$line;
			$idx++;
		} 
		if(!(strpos($line,'document.write(unescape(')===false)) {
			// another bad boy
			$ansa[$idx]=$n.': '.$line;
			$idx++;
		} 
		if(!(strpos($line,'try{window.onload')===false)) {
			// another bad boy
			$ansa[$idx]=$n.': '.$line;
			$idx++;
		} 
		if(!(strpos($line,"setAttribute('src'")===false)) {
			// another bad boy
			$ansa[$idx]=$n.': '.$line;
			$idx++;
		} 
		
	}
	fclose($handle);
	return $ansa;
}
	
	
	
	 
?>