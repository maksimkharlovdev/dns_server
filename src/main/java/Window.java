import javax.swing.*;
import javax.swing.border.BevelBorder;
import java.util.concurrent.atomic.AtomicBoolean;

public class Window extends JFrame {
    public Window(AtomicBoolean stopped) {
        super();
        setVisible(true);
        setSize(400, 300);
        setTitle("DNS Server");

        JButton stopButton = new JButton("Stop!");
        stopButton.addActionListener(event -> {
            stopped.set(true);
            closeWindow();
        });
        stopButton.setBounds(170, 140, 60, 20);
        stopButton.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
        add(stopButton);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
    }

    private void closeWindow() {
        dispose();
    }
}
