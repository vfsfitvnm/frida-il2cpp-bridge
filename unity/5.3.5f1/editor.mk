include ../editor.mk

$(EDITOR_DIR):
	@ $(ECHO) downloading editor...
	@ $(CURL) "http://download.unity3d.com/download_unity/linux/unity-editor-5.3.5f1+20160525_amd64.deb" -o editor.deb

	@ $(ECHO) extracting editor...
	@ ar x editor.deb
	@ tar -xf data.tar.gz --strip-components=3 --exclude="usr*" --exclude="opt/Unity/MonoDevelop*"

	@ ar t editor.deb | xargs rm
	@ rm editor.deb
	@ touch -m Editor
